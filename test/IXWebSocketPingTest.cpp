/*
 *  IXWebSocketPingTest.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone. All rights reserved.
 */

#include "IXTest.h"
#include "catch.hpp"
#include <iostream>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketServer.h>
#include <queue>
#include <sstream>

using namespace ix;

namespace
{
    class WebSocketClient
    {
    public:
        WebSocketClient(int port);

        void start();
        void stop();
        bool isReady() const;
        void sendMessage(const std::string& text);

    private:
        ix::WebSocket _webSocket;
        int _port;
    };

    WebSocketClient::WebSocketClient(int port)
        : _port(port)
    {
        ;
    }

    bool WebSocketClient::isReady() const
    {
        return _webSocket.getReadyState() == ix::ReadyState::Open;
    }

    void WebSocketClient::stop()
    {
        _webSocket.stop();
    }

    void WebSocketClient::start()
    {
        std::string url;
        {
            std::stringstream ss;
            ss << "ws://127.0.0.1:" << _port << "/";

            url = ss.str();
        }

        _webSocket.setUrl(url);

        // The important bit for this test.
        // Set a 1 second heartbeat with the setter method to test
        _webSocket.setPingInterval(1);

        std::stringstream ss;
        log(std::string("Connecting to url: ") + url);

        _webSocket.setOnMessageCallback([](const ix::WebSocketMessagePtr& msg) {
            std::stringstream ss;
            if (msg->type == ix::WebSocketMessageType::Open)
            {
                log("client connected");
            }
            else if (msg->type == ix::WebSocketMessageType::Close)
            {
                log("client disconnected");
            }
            else if (msg->type == ix::WebSocketMessageType::Error)
            {
                ss << "Error ! " << msg->errorInfo.reason;
                log(ss.str());
            }
            else if (msg->type == ix::WebSocketMessageType::Pong)
            {
                ss << "Received pong message " << msg->str;
                log(ss.str());
            }
            else if (msg->type == ix::WebSocketMessageType::Ping)
            {
                ss << "Received ping message " << msg->str;
                log(ss.str());
            }
            else if (msg->type == ix::WebSocketMessageType::Message)
            {
                // too many messages to log
            }
            else
            {
                ss << "Invalid ix::WebSocketMessageType";
                log(ss.str());
            }
        });

        _webSocket.start();
    }

    void WebSocketClient::sendMessage(const std::string& text)
    {
        _webSocket.send(text);
    }

    bool startServer(ix::WebSocketServer& server, std::atomic<int>& receivedPingMessages)
    {
        // A dev/null server
        server.setOnClientMessageCallback(
            [&server, &receivedPingMessages](std::shared_ptr<ConnectionState> connectionState,
                                             WebSocket& webSocket,
                                             const ix::WebSocketMessagePtr& msg) {
                if (msg->type == ix::WebSocketMessageType::Open)
                {
                    TLogger() << "New server connection";
                    TLogger() << "id: " << connectionState->getId();
                    TLogger() << "Uri: " << msg->openInfo.uri;
                    TLogger() << "Headers:";
                    for (auto it : msg->openInfo.headers)
                    {
                        TLogger() << it.first << ": " << it.second;
                    }
                }
                else if (msg->type == ix::WebSocketMessageType::Close)
                {
                    log("Server closed connection");
                }
                else if (msg->type == ix::WebSocketMessageType::Ping)
                {
                    log("Server received a ping");
                    receivedPingMessages++;
                }
                else if (msg->type == ix::WebSocketMessageType::Message)
                {
                    // too many messages to log
                    for (auto&& client : server.getClients())
                    {
                        if (client.first.get() != &webSocket)
                        {
                            client.first->sendText("reply");
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
} // namespace

TEST_CASE("Websocket_ping_no_data_sent_setPingInterval", "[setPingInterval]")
{
    SECTION("Make sure that ping messages are sent when no other data are sent.")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        REQUIRE(startServer(server, serverReceivedPingMessages));

        std::string session = ix::generateSessionId();
        WebSocketClient webSocketClient(port);

        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(10);
        }

        REQUIRE(server.getClients().size() == 1);

        ix::msleep(2100);

        webSocketClient.stop();


        // Here we test ping interval
        // -> expected at least 2 ping messages (first ping can be sent on connect)
        REQUIRE(serverReceivedPingMessages >= 2);

        // Give us 1000ms for the server to notice that clients went away
        ix::msleep(1000);
        REQUIRE(server.getClients().size() == 0);

        ix::reportWebSocketTraffic();
    }
}

TEST_CASE("Websocket_ping_data_sent_setPingInterval", "[setPingInterval]")
{
    SECTION("Make sure that ping messages are sent, even if other messages are sent")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        REQUIRE(startServer(server, serverReceivedPingMessages));

        std::string session = ix::generateSessionId();
        WebSocketClient webSocketClient(port);

        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(10);
        }

        REQUIRE(server.getClients().size() == 1);

        ix::msleep(900);
        webSocketClient.sendMessage("hello world");
        ix::msleep(900);
        webSocketClient.sendMessage("hello world");
        ix::msleep(1300);

        webSocketClient.stop();

        // Here we test ping interval
        // client has sent data, but ping should have been sent no matter what
        // -> expected at least 2 ping messages even while data messages are sent
        REQUIRE(serverReceivedPingMessages >= 2);

        // Give us 1000ms for the server to notice that clients went away
        ix::msleep(1000);
        REQUIRE(server.getClients().size() == 0);

        ix::reportWebSocketTraffic();
    }
}

TEST_CASE("Websocket_ping_data_sent_setPingInterval_half_full", "[setPingInterval]")
{
    SECTION("Make sure that ping messages are sent, even if other messages are sent continuously "
            "during a given time")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        REQUIRE(startServer(server, serverReceivedPingMessages));

        std::string session = ix::generateSessionId();
        WebSocketClient webSocketClient(port);

        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(10);
        }

        REQUIRE(server.getClients().size() == 1);

        // send continuously for 1100ms
        auto now = std::chrono::steady_clock::now();

        while (std::chrono::steady_clock::now() - now <= std::chrono::milliseconds(900))
        {
            webSocketClient.sendMessage("message");
            ix::msleep(1);
        }
        ix::msleep(150);

        // Here we test ping interval
        // client has sent data, but ping should have been sent no matter what
        // -> expected at least 1 ping message
        REQUIRE(serverReceivedPingMessages >= 1);

        ix::msleep(100);

        webSocketClient.stop();

        // Give us 1000ms for the server to notice that clients went away
        ix::msleep(1000);
        REQUIRE(server.getClients().size() == 0);

        ix::reportWebSocketTraffic();
    }
}

TEST_CASE("Websocket_ping_data_sent_setPingInterval_full", "[setPingInterval]")
{
    SECTION("Make sure that ping messages are sent, even if other messages are sent continuously "
            "for longer than ping interval")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        REQUIRE(startServer(server, serverReceivedPingMessages));

        std::string session = ix::generateSessionId();
        WebSocketClient webSocketClient(port);

        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(1);
        }

        REQUIRE(server.getClients().size() == 1);

        // send continuously for 1100ms
        auto now = std::chrono::steady_clock::now();

        while (std::chrono::steady_clock::now() - now <= std::chrono::milliseconds(1100))
        {
            webSocketClient.sendMessage("message");
            ix::msleep(1);
        }

        // Here we test ping interval
        // client has sent data, but ping should have been sent no matter what
        // -> expected at least 2 ping messages (first ping can be sent on connect)
        REQUIRE(serverReceivedPingMessages >= 2);

        ix::msleep(100);

        webSocketClient.stop();

        // Give us 1000ms for the server to notice that clients went away
        ix::msleep(1000);
        REQUIRE(server.getClients().size() == 0);

        ix::reportWebSocketTraffic();
    }
}

// Using setPingInterval

TEST_CASE("Websocket_ping_no_data_sent_setHeartBeatPeriod", "[setPingInterval]")
{
    SECTION("Make sure that ping messages are sent when no other data are sent.")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        REQUIRE(startServer(server, serverReceivedPingMessages));

        std::string session = ix::generateSessionId();
        WebSocketClient webSocketClient(port);

        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(1);
        }

        REQUIRE(server.getClients().size() == 1);

        ix::msleep(2100);

        webSocketClient.stop();

        // Here we test ping interval
        // -> expected at least 2 ping messages (first ping can be sent on connect)
        REQUIRE(serverReceivedPingMessages >= 2);

        // Give us 1000ms for the server to notice that clients went away
        ix::msleep(1000);
        REQUIRE(server.getClients().size() == 0);

        ix::reportWebSocketTraffic();
        server.stop();
    }
}

TEST_CASE("Websocket_ping_data_sent_setHeartBeatPeriod", "[setPingInterval]")
{
    SECTION("Make sure that ping messages are sent, even if other messages are sent")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        REQUIRE(startServer(server, serverReceivedPingMessages));

        std::string session = ix::generateSessionId();
        WebSocketClient webSocketClient(port);

        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(1);
        }

        REQUIRE(server.getClients().size() == 1);

        ix::msleep(900);
        webSocketClient.sendMessage("hello world");
        ix::msleep(900);
        webSocketClient.sendMessage("hello world");
        ix::msleep(1100);

        webSocketClient.stop();

        // without this sleep test fails on Windows
        ix::msleep(100);

        // Here we test ping interval
        // client has sent data, but ping should have been sent no matter what
        // -> expected at least 2 ping messages
        REQUIRE(serverReceivedPingMessages >= 2);

        // Give us 1000ms for the server to notice that clients went away
        ix::msleep(1000);
        REQUIRE(server.getClients().size() == 0);

        ix::reportWebSocketTraffic();
        server.stop();
    }
}
