/*
 *  IXWebSocketHeartBeatNoResponseAutoDisconnectTest.cpp
 *  Author: Alexandre Konieczny
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
        WebSocketClient(int port, int pingInterval, int pingTimeout);

        void start();
        void stop();
        bool isReady() const;
        bool isClosed() const;
        int getReceivedPongMessages();
        bool closedDueToPingTimeout();

    private:
        ix::WebSocket _webSocket;
        int _port;
        int _pingInterval;
        int _pingTimeout;
        std::atomic<int> _receivedPongMessages;
        std::atomic<bool> _closedDueToPingTimeout;
    };

    WebSocketClient::WebSocketClient(int port, int pingInterval, int pingTimeout)
        : _port(port)
        , _pingInterval(pingInterval)
        , _pingTimeout(pingTimeout)
        , _receivedPongMessages(0)
        , _closedDueToPingTimeout(false)
    {
        ;
    }

    bool WebSocketClient::isReady() const
    {
        return _webSocket.getReadyState() == ix::ReadyState::Open;
    }

    bool WebSocketClient::isClosed() const
    {
        return _webSocket.getReadyState() == ix::ReadyState::Closed;
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
        _webSocket.setAutomaticReconnection(false);

        // The important bit for this test.
        // Set a ping interval, and a ping timeout
        ix::WebSocketTimeouts timeouts;
        timeouts.setPingInterval(_pingInterval).setPingTimeout(_pingTimeout);
        _webSocket.setTimeouts(timeouts);

        std::stringstream ss;
        log(std::string("Connecting to url: ") + url);

        _webSocket.setOnMessageCallback([this](const ix::WebSocketMessagePtr& msg) {
            std::stringstream ss;
            if (msg->type == ix::WebSocketMessageType::Open)
            {
                log("client connected");
            }
            else if (msg->type == ix::WebSocketMessageType::Close)
            {
                log("client disconnected");

                if (msg->closeInfo.code == 1011)
                {
                    _closedDueToPingTimeout = true;
                }
            }
            else if (msg->type == ix::WebSocketMessageType::Error)
            {
                ss << "Error ! " << msg->errorInfo.reason;
                log(ss.str());
            }
            else if (msg->type == ix::WebSocketMessageType::Pong)
            {
                _receivedPongMessages++;

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
                ss << "Received message " << msg->str;
                log(ss.str());
            }
            else
            {
                ss << "Invalid ix::WebSocketMessageType";
                log(ss.str());
            }
        });

        _webSocket.start();
    }

    int WebSocketClient::getReceivedPongMessages()
    {
        return _receivedPongMessages;
    }

    bool WebSocketClient::closedDueToPingTimeout()
    {
        return _closedDueToPingTimeout;
    }

    bool startServer(ix::WebSocketServer& server,
                     std::atomic<int>& receivedPingMessages,
                     bool enablePong)
    {
        // A dev/null server
        server.setOnClientMessageCallback(
            [&receivedPingMessages](std::shared_ptr<ConnectionState> connectionState,
                                    WebSocket& webSocket,
                                    const ix::WebSocketMessagePtr& msg) {
                (void) webSocket;

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
            });

        server.setPong(enablePong);

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

TEST_CASE("Websocket_ping_timeout_not_checked", "[setPingTimeout]")
{
    SECTION("Make sure that ping messages have a response (PONG).")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        bool enablePong = false; // Pong is disabled on Server
        REQUIRE(startServer(server, serverReceivedPingMessages, enablePong));

        std::string session = ix::generateSessionId();
        int pingIntervalSecs = 1;
        int pingTimeoutSecs = 5; // keep timeout larger than the test window
        WebSocketClient webSocketClient(port, pingIntervalSecs, pingTimeoutSecs);

        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(10);
        }

        REQUIRE(server.getClients().size() == 1);

        ix::msleep(1100);

        // Here we test ping timeout, no timeout
        REQUIRE(serverReceivedPingMessages >= 1);
        REQUIRE(webSocketClient.getReceivedPongMessages() == 0);

        ix::msleep(1000);

        // Here we test ping timeout, no timeout
        REQUIRE(serverReceivedPingMessages >= 2);
        REQUIRE(webSocketClient.getReceivedPongMessages() == 0);

        webSocketClient.stop();

        // Give us 1000ms for the server to notice that clients went away
        ix::msleep(1000);
        REQUIRE(server.getClients().size() == 0);

        // Ensure client close was not by ping timeout
        REQUIRE(webSocketClient.closedDueToPingTimeout() == false);

        ix::reportWebSocketTraffic();
    }
}

TEST_CASE("Websocket_ping_no_timeout", "[setPingTimeout]")
{
    SECTION("Make sure that ping messages have a response (PONG).")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        bool enablePong = true; // Pong is enabled on Server
        REQUIRE(startServer(server, serverReceivedPingMessages, enablePong));

        std::string session = ix::generateSessionId();
        int pingIntervalSecs = 1;
        int pingTimeoutSecs = 2;
        WebSocketClient webSocketClient(port, pingIntervalSecs, pingTimeoutSecs);

        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(10);
        }

        REQUIRE(server.getClients().size() == 1);

        ix::msleep(1200);

        // Here we test ping timeout, no timeout
        REQUIRE(serverReceivedPingMessages >= 1);
        REQUIRE(webSocketClient.getReceivedPongMessages() >= 1);

        ix::msleep(1000);

        // Here we test ping timeout, no timeout
        REQUIRE(serverReceivedPingMessages >= 2);
        REQUIRE(webSocketClient.getReceivedPongMessages() >= 2);

        webSocketClient.stop();

        // Give us 1000ms for the server to notice that clients went away
        ix::msleep(1000);
        REQUIRE(server.getClients().size() == 0);

        // Ensure client close was not by ping timeout
        REQUIRE(webSocketClient.closedDueToPingTimeout() == false);

        ix::reportWebSocketTraffic();
    }
}

TEST_CASE("Websocket_no_ping_but_timeout", "[setPingTimeout]")
{
    SECTION("Make sure that ping messages don't have responses (no PONG).")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        bool enablePong = false; // Pong is disabled on Server
        REQUIRE(startServer(server, serverReceivedPingMessages, enablePong));

        std::string session = ix::generateSessionId();
        int pingIntervalSecs = -1; // no ping set
        int pingTimeoutSecs = 3;
        WebSocketClient webSocketClient(port, pingIntervalSecs, pingTimeoutSecs);
        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(10);
        }

        REQUIRE(server.getClients().size() == 1);

        ix::msleep(2900);

        // Here we test ping timeout, no timeout yet
        REQUIRE(serverReceivedPingMessages == 0);
        REQUIRE(webSocketClient.getReceivedPongMessages() == 0);

        REQUIRE(webSocketClient.isClosed() == false);
        REQUIRE(webSocketClient.closedDueToPingTimeout() == false);

        ix::msleep(300);

        // Here we test ping timeout, timeout
        REQUIRE(serverReceivedPingMessages == 0);
        REQUIRE(webSocketClient.getReceivedPongMessages() == 0);
        // Ensure client close was by ping timeout
        ix::msleep(1000);
        REQUIRE(webSocketClient.isClosed() == true);
        REQUIRE(webSocketClient.closedDueToPingTimeout() == true);

        webSocketClient.stop();

        REQUIRE(server.getClients().size() == 0);

        ix::reportWebSocketTraffic();
    }
}

TEST_CASE("Websocket_ping_timeout", "[setPingTimeout]")
{
    SECTION("Make sure that ping messages don't have responses (no PONG).")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        bool enablePong = false; // Pong is disabled on Server
        REQUIRE(startServer(server, serverReceivedPingMessages, enablePong));

        std::string session = ix::generateSessionId();
        int pingIntervalSecs = 1;
        int pingTimeoutSecs = 2;
        WebSocketClient webSocketClient(port, pingIntervalSecs, pingTimeoutSecs);

        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(10);
        }

        REQUIRE(server.getClients().size() == 1);

        ix::msleep(1100);

        // Here we test ping timeout, no timeout yet
        REQUIRE(serverReceivedPingMessages >= 1);
        REQUIRE(webSocketClient.getReceivedPongMessages() == 0);

        ix::msleep(1100);

        // Here we test ping timeout, timeout
        REQUIRE(serverReceivedPingMessages >= 2);
        REQUIRE(webSocketClient.getReceivedPongMessages() == 0);
        // Ensure client close was by ping timeout
        ix::msleep(1000);
        REQUIRE(webSocketClient.isClosed() == true);
        REQUIRE(webSocketClient.closedDueToPingTimeout() == true);

        webSocketClient.stop();

        REQUIRE(server.getClients().size() == 0);

        ix::reportWebSocketTraffic();
    }
}

TEST_CASE("Websocket_ping_long_timeout", "[setPingTimeout]")
{
    SECTION("Make sure that ping messages don't have responses (no PONG).")
    {
        ix::setupWebSocketTrafficTrackerCallback();

        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> serverReceivedPingMessages(0);
        bool enablePong = false; // Pong is disabled on Server
        REQUIRE(startServer(server, serverReceivedPingMessages, enablePong));

        std::string session = ix::generateSessionId();
        int pingIntervalSecs = 2;
        int pingTimeoutSecs = 6;
        WebSocketClient webSocketClient(port, pingIntervalSecs, pingTimeoutSecs);

        webSocketClient.start();

        // Wait for all chat instance to be ready
        while (true)
        {
            if (webSocketClient.isReady()) break;
            ix::msleep(10);
        }

        REQUIRE(server.getClients().size() == 1);

        ix::msleep(5800);

        // Here we test ping timeout, no timeout yet (2 ping sent at 2s and 4s)
        REQUIRE(serverReceivedPingMessages >= 2);
        REQUIRE(webSocketClient.getReceivedPongMessages() == 0);

        // Ensure client not closed
        REQUIRE(webSocketClient.isClosed() == false);
        REQUIRE(webSocketClient.closedDueToPingTimeout() == false);

        ix::msleep(600);

        // Here we test ping timeout, timeout (at 6 seconds)
        REQUIRE(serverReceivedPingMessages >= 2);
        REQUIRE(webSocketClient.getReceivedPongMessages() == 0);
        // Ensure client close was not by ping timeout
        REQUIRE(webSocketClient.isClosed() == true);
        REQUIRE(webSocketClient.closedDueToPingTimeout() == true);

        webSocketClient.stop();

        REQUIRE(server.getClients().size() == 0);

        ix::reportWebSocketTraffic();
    }
}
