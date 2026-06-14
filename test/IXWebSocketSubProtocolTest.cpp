/*
 *  IXWebSocketServerTest.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone. All rights reserved.
 */

#include "IXTest.h"
#include "catch.hpp"
#include <iostream>
#include <ixwebsocket/IXSocket.h>
#include <ixwebsocket/IXSocketFactory.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketServer.h>

using namespace ix;

bool startServer(ix::WebSocketServer& server, std::string& subProtocols)
{
    server.setOnClientMessageCallback(
        [&server, &subProtocols](std::shared_ptr<ConnectionState> connectionState,
                                 WebSocket& webSocket,
                                 const ix::WebSocketMessagePtr& msg) {
            auto remoteIp = connectionState->getRemoteIp();
            if (msg->type == ix::WebSocketMessageType::Open)
            {
                TLogger() << "New connection";
                TLogger() << "remote ip: " << remoteIp;
                TLogger() << "id: " << connectionState->getId();
                TLogger() << "Uri: " << msg->openInfo.uri;
                TLogger() << "Headers:";
                for (auto it : msg->openInfo.headers)
                {
                    TLogger() << it.first << ": " << it.second;
                }

                subProtocols = msg->openInfo.headers["Sec-WebSocket-Protocol"];
            }
            else if (msg->type == ix::WebSocketMessageType::Close)
            {
                log("Closed connection");
            }
            else if (msg->type == ix::WebSocketMessageType::Message)
            {
                for (auto&& client : server.getClients())
                {
                    if (client.first.get() != &webSocket)
                    {
                        client.first->sendBinary(msg->str);
                    }
                }
            }
        });

    auto err = server.listen();
    if (err)
    {
        log(*err);
        return false;
    }

    server.start();
    return true;
}

TEST_CASE("subprotocol", "[websocket_subprotocol]")
{
    SECTION("Connect to the server")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);

        std::string subProtocols;
        startServer(server, subProtocols);

        std::atomic<bool> connected(false);
        ix::WebSocket webSocket;
        webSocket.setOnMessageCallback([&connected](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Open)
            {
                connected = true;
                log("Client connected");
            }
        });

        webSocket.addSubProtocol("json");
        webSocket.addSubProtocol("msgpack");

        std::string url;
        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port;
        url = ss.str();

        webSocket.setUrl(url);
        webSocket.start();

        // Give us 3 seconds to connect
        int attempts = 0;
        while (!connected)
        {
            REQUIRE(attempts++ < 300);
            ix::msleep(10);
        }

        webSocket.stop();
        server.stop();

        REQUIRE(subProtocols == "json,msgpack");
    }

    SECTION("Server subprotocol selection requires exact token match")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        server.addSubProtocol("json");

        std::string subProtocols;
        REQUIRE(startServer(server, subProtocols));

        std::atomic<bool> connected(false);
        std::string selectedProtocol;

        ix::WebSocket webSocket;
        webSocket.setOnMessageCallback(
            [&connected, &selectedProtocol](const ix::WebSocketMessagePtr& msg) {
                if (msg->type == ix::WebSocketMessageType::Open)
                {
                    connected = true;
                    selectedProtocol = msg->openInfo.protocol;
                }
            });

        webSocket.addSubProtocol("json-v2");

        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port;
        webSocket.setUrl(ss.str());
        webSocket.start();

        int attempts = 0;
        while (!connected)
        {
            REQUIRE(attempts++ < 300);
            ix::msleep(10);
        }

        webSocket.stop();
        server.stop();

        REQUIRE(subProtocols == "json-v2");
        REQUIRE(selectedProtocol.empty());
    }

    SECTION("Client and server ignore invalid configured subprotocol tokens")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        server.addSubProtocol("bad token");

        std::string subProtocols;
        REQUIRE(startServer(server, subProtocols));

        ix::WebSocket webSocket;
        webSocket.setOnMessageCallback([](const ix::WebSocketMessagePtr&) {});
        webSocket.addSubProtocol("bad token");

        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port;
        webSocket.setUrl(ss.str());

        auto result = webSocket.connect(3);
        webSocket.stop();
        server.stop();

        REQUIRE(result.success);
        REQUIRE(subProtocols.empty());
        REQUIRE(result.protocol.empty());
    }
}
