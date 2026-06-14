/*
 *  IXWebSocketServerTest.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone. All rights reserved.
 */

#include "IXTest.h"
#include "catch.hpp"
#include <array>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <sstream>
#include <ixwebsocket/IXCancellationRequest.h>
#include <ixwebsocket/IXSocket.h>
#include <ixwebsocket/IXSocketFactory.h>
#include <ixwebsocket/IXSocketServer.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketCloseConstants.h>
#include <ixwebsocket/IXWebSocketHandshakeKeyGen.h>
#include <ixwebsocket/IXWebSocketServer.h>
#include <ixwebsocket/IXWebSocketTransport.h>

using namespace ix;

namespace ix
{
    const std::string kValidSecWebSocketKey("dGhlIHNhbXBsZSBub25jZQ==");

    // Test that we can override the connectionState impl to provide our own
    class ConnectionStateCustom : public ConnectionState
    {
        void computeId()
        {
            // a very boring invariant id that we can test against in the unittest
            _id = "foobarConnectionId";
        }
    };

    bool startServer(ix::WebSocketServer& server, std::string& connectionId)
    {
        auto factory = []() -> std::shared_ptr<ConnectionState> {
            return std::make_shared<ConnectionStateCustom>();
        };
        server.setConnectionStateFactory(factory);

        server.setOnClientMessageCallback(
            [&server, &connectionId](std::shared_ptr<ConnectionState> connectionState,
                                     WebSocket& webSocket,
                                     const ix::WebSocketMessagePtr& msg) {
                auto remoteIp = connectionState->getRemoteIp();

                if (msg->type == ix::WebSocketMessageType::Open)
                {
                    TLogger() << "New connection";
                    connectionState->computeId();
                    TLogger() << "remote ip: " << remoteIp;
                    TLogger() << "id: " << connectionState->getId();
                    TLogger() << "Uri: " << msg->openInfo.uri;
                    TLogger() << "Headers:";
                    for (auto it : msg->openInfo.headers)
                    {
                        TLogger() << it.first << ": " << it.second;
                    }

                    connectionId = connectionState->getId();
                }
                else if (msg->type == ix::WebSocketMessageType::Close)
                {
                    TLogger() << "Closed connection";
                }
                else if (msg->type == ix::WebSocketMessageType::Message)
                {
                    for (auto&& client : server.getClients())
                    {
                        if (client.first.get() != &webSocket)
                        {
                            client.first->send(msg->str, msg->binary);
                        }
                    }
                }
            });

        auto err = server.listen();
        if (err)
        {
            TLogger() << *err;
            return false;
        }

        server.start();
        return true;
    }

    bool neverCancel()
    {
        return false;
    }

    class ScriptedHandshakeServer final : public SocketServer
    {
    public:
        ScriptedHandshakeServer(int port, std::string connectionHeader)
            : SocketServer(port, "127.0.0.1")
            , _connectionHeader(std::move(connectionHeader))
        {
        }

    private:
        void handleConnection(std::unique_ptr<ix::Socket> socket,
                              std::shared_ptr<ix::ConnectionState> connectionState) final
        {
            std::string key;

            auto requestLine = socket->readLine(neverCancel);
            if (requestLine)
            {
                while (true)
                {
                    auto line = socket->readLine(neverCancel);
                    if (!line || *line == "\r\n")
                    {
                        break;
                    }

                    auto colon = line->find(':');
                    if (colon == std::string::npos)
                    {
                        continue;
                    }

                    std::string name = line->substr(0, colon);
                    std::string value = line->substr(colon + 1);

                    while (!value.empty() && (value[0] == ' ' || value[0] == '\t'))
                    {
                        value.erase(value.begin());
                    }

                    while (!value.empty() && (value.back() == '\r' || value.back() == '\n'))
                    {
                        value.pop_back();
                    }

                    if (caseInsensitiveEquals(name, "Sec-WebSocket-Key"))
                    {
                        key = value;
                    }
                }
            }

            char output[29] = {};
            WebSocketHandshakeKeyGen::generate(key, output);

            std::stringstream response;
            response << "HTTP/1.1 101 Switching Protocols\r\n";
            response << "Upgrade: websocket\r\n";
            response << "Connection: " << _connectionHeader << "\r\n";
            response << "Sec-WebSocket-Accept: " << output << "\r\n";
            response << "\r\n";

            socket->writeBytes(response.str(), neverCancel);
            connectionState->setTerminated();
        }

        size_t getConnectedClientsCount() final
        {
            return 0;
        }

        std::string _connectionHeader;
    };

    class QueryRedirectHandshakeServer final : public SocketServer
    {
    public:
        explicit QueryRedirectHandshakeServer(int port)
            : SocketServer(port, "127.0.0.1")
        {
        }

    private:
        void handleConnection(std::unique_ptr<ix::Socket> socket,
                              std::shared_ptr<ix::ConnectionState> connectionState) final
        {
            std::string key;
            auto requestLine = socket->readLine(neverCancel);
            if (!requestLine)
            {
                connectionState->setTerminated();
                return;
            }

            while (true)
            {
                auto line = socket->readLine(neverCancel);
                if (!line || *line == "\r\n")
                {
                    break;
                }

                auto colon = line->find(':');
                if (colon == std::string::npos)
                {
                    continue;
                }

                std::string name = line->substr(0, colon);
                std::string value = line->substr(colon + 1);

                while (!value.empty() && (value[0] == ' ' || value[0] == '\t'))
                {
                    value.erase(value.begin());
                }

                while (!value.empty() && (value.back() == '\r' || value.back() == '\n'))
                {
                    value.pop_back();
                }

                if (caseInsensitiveEquals(name, "Sec-WebSocket-Key"))
                {
                    key = value;
                }
            }

            if (requestLine->find(" /redirect?old=1 ") != std::string::npos)
            {
                socket->writeBytes("HTTP/1.1 302 Found\r\n"
                                   "Location: ?new=1\r\n"
                                   "Content-Length: 0\r\n"
                                   "Connection: close\r\n"
                                   "\r\n",
                                   neverCancel);
                connectionState->setTerminated();
                return;
            }

            if (requestLine->find(" /redirect?new=1 ") != std::string::npos)
            {
                char output[29] = {};
                WebSocketHandshakeKeyGen::generate(key, output);

                std::stringstream response;
                response << "HTTP/1.1 101 Switching Protocols\r\n";
                response << "Upgrade: websocket\r\n";
                response << "Connection: Upgrade\r\n";
                response << "Sec-WebSocket-Accept: " << output << "\r\n";
                response << "\r\n";

                socket->writeBytes(response.str(), neverCancel);
                connectionState->setTerminated();
                return;
            }

            socket->writeBytes("HTTP/1.1 404 Not Found\r\n"
                               "Content-Length: 0\r\n"
                               "Connection: close\r\n"
                               "\r\n",
                               neverCancel);
            connectionState->setTerminated();
        }

        size_t getConnectedClientsCount() final
        {
            return 0;
        }
    };

    class TwoConnectionFrameServer final : public SocketServer
    {
    public:
        explicit TwoConnectionFrameServer(int port)
            : SocketServer(port, "127.0.0.1")
        {
        }

        std::atomic<bool> firstConnectionHandled{false};
        std::atomic<bool> secondConnectionHandled{false};

    private:
        void handleConnection(std::unique_ptr<ix::Socket> socket,
                              std::shared_ptr<ix::ConnectionState> connectionState) final
        {
            std::string key;
            auto requestLine = socket->readLine(neverCancel);
            if (!requestLine)
            {
                connectionState->setTerminated();
                return;
            }

            while (true)
            {
                auto line = socket->readLine(neverCancel);
                if (!line || *line == "\r\n")
                {
                    break;
                }

                auto colon = line->find(':');
                if (colon == std::string::npos)
                {
                    continue;
                }

                std::string name = line->substr(0, colon);
                std::string value = line->substr(colon + 1);
                while (!value.empty() && (value[0] == ' ' || value[0] == '\t'))
                {
                    value.erase(value.begin());
                }
                while (!value.empty() && (value.back() == '\r' || value.back() == '\n'))
                {
                    value.pop_back();
                }

                if (caseInsensitiveEquals(name, "Sec-WebSocket-Key"))
                {
                    key = value;
                }
            }

            char output[29] = {};
            WebSocketHandshakeKeyGen::generate(key, output);

            std::stringstream response;
            response << "HTTP/1.1 101 Switching Protocols\r\n";
            response << "Upgrade: websocket\r\n";
            response << "Connection: Upgrade\r\n";
            response << "Sec-WebSocket-Accept: " << output << "\r\n";
            response << "\r\n";
            socket->writeBytes(response.str(), neverCancel);

            if (!firstConnectionHandled.exchange(true))
            {
                std::string frame;
                frame.push_back(static_cast<char>(0x01)); // text, FIN clear
                frame.push_back(static_cast<char>(0x05));
                frame += "stale";
                socket->writeBytes(frame, neverCancel);
                socket->close();
            }
            else
            {
                std::string frame;
                frame.push_back(static_cast<char>(0x80)); // final continuation
                frame.push_back(static_cast<char>(0x05));
                frame += "-data";
                socket->writeBytes(frame, neverCancel);
                ix::msleep(200);
                socket->close();
                secondConnectionHandled = true;
            }

            connectionState->setTerminated();
        }

        size_t getConnectedClientsCount() final
        {
            return 0;
        }
    };

    class ScriptedSocket final : public Socket
    {
    public:
        explicit ScriptedSocket(const std::string& scriptedReadData)
            : Socket(-1)
            , _scriptedReadData(scriptedReadData)
        {
        }

        IoResult send(const char* buffer, size_t length) final
        {
            _writtenData.append(buffer, length);
            return {length, IoError::Success};
        }

        IoResult recv(void* buffer, size_t length) final
        {
            if (_readOffset >= _scriptedReadData.size())
            {
                return {0, IoError::ConnectionClosed};
            }

            size_t bytesToCopy = std::min(length, _scriptedReadData.size() - _readOffset);
            memcpy(buffer, _scriptedReadData.data() + _readOffset, bytesToCopy);
            _readOffset += bytesToCopy;
            return {bytesToCopy, IoError::Success};
        }

    private:
        std::string _scriptedReadData;
        std::string _writtenData;
        size_t _readOffset = 0;
    };

    class MaxConnectionSocketServer final : public SocketServer
    {
    public:
        explicit MaxConnectionSocketServer(int port)
            : SocketServer(port, "127.0.0.1", SocketServer::kDefaultTcpBacklog, 1)
        {
        }

        std::atomic<size_t> handledConnections{0};
        std::atomic<bool> releaseConnections{false};

    private:
        void handleConnection(std::unique_ptr<ix::Socket>,
                              std::shared_ptr<ix::ConnectionState> connectionState) final
        {
            ++handledConnections;
            while (!releaseConnections)
            {
                ix::msleep(10);
            }
            connectionState->setTerminated();
        }

        size_t getConnectedClientsCount() final
        {
            return 0;
        }
    };

    std::shared_ptr<Socket> connectRawSocket(int port)
    {
        std::string errMsg;
        bool tls = false;
        SocketTLSOptions tlsOptions;
        std::shared_ptr<Socket> socket = createSocket(tls, -1, errMsg, tlsOptions);
        std::string host("127.0.0.1");
        bool success = socket->connect(host, port, errMsg, neverCancel);
        REQUIRE(success);
        return socket;
    }

    void sendHandshakeAndRequireStatus(std::shared_ptr<Socket> socket,
                                       const std::string& host,
                                       int port,
                                       const std::string& extraHeaders,
                                       int expectedStatus,
                                       const std::string& secWebSocketKey = kValidSecWebSocketKey,
                                       const std::string& secWebSocketVersion = "13")
    {
        std::stringstream request;
        request << "GET / HTTP/1.1\r\n";
        request << "Host: " << host << ":" << port << "\r\n";
        request << "Upgrade: websocket\r\n";
        request << "Sec-WebSocket-Version: " << secWebSocketVersion << "\r\n";
        request << "Sec-WebSocket-Key: " << secWebSocketKey << "\r\n";
        request << extraHeaders;
        request << "\r\n";

        REQUIRE(socket->writeBytes(request.str(), neverCancel));

        auto lineResult = socket->readLine(neverCancel);
        REQUIRE(lineResult.has_value());

        auto line = *lineResult;

        int status = -1;
        REQUIRE(sscanf(line.c_str(), "HTTP/1.1 %d", &status) == 1);
        REQUIRE(status == expectedStatus);

        if (expectedStatus == 101)
        {
            while (true)
            {
                auto headerLine = socket->readLine(neverCancel);
                REQUIRE(headerLine.has_value());
                if (*headerLine == "\r\n")
                {
                    break;
                }
            }
        }
    }

    void readHeadersUntilBlankLine(std::shared_ptr<Socket> socket)
    {
        std::atomic<bool> cancelled(false);
        auto cancellation = makeCancellationRequestWithTimeout(3, cancelled);

        while (true)
        {
            auto headerLine = socket->readLine(cancellation);
            REQUIRE(headerLine.has_value());
            if (*headerLine == "\r\n")
            {
                break;
            }
        }
    }

    std::optional<uint16_t> readCloseCode(std::shared_ptr<Socket> socket, int timeoutSecs)
    {
        std::atomic<bool> cancelled(false);
        auto cancellation = makeCancellationRequestWithTimeout(timeoutSecs, cancelled);

        auto firstBytes = socket->readBytes(2, nullptr, nullptr, cancellation);
        if (!firstBytes || firstBytes->size() != 2)
        {
            return std::nullopt;
        }

        uint8_t byte0 = static_cast<uint8_t>((*firstBytes)[0]);
        uint8_t byte1 = static_cast<uint8_t>((*firstBytes)[1]);

        uint8_t opcode = byte0 & 0x0f;
        if (opcode != 0x8)
        {
            return std::nullopt;
        }

        bool masked = (byte1 & 0x80) != 0;
        uint64_t payloadSize = byte1 & 0x7f;

        if (payloadSize == 126)
        {
            auto extended = socket->readBytes(2, nullptr, nullptr, cancellation);
            if (!extended || extended->size() != 2)
            {
                return std::nullopt;
            }

            payloadSize = (static_cast<uint8_t>((*extended)[0]) << 8) |
                          static_cast<uint8_t>((*extended)[1]);
        }
        else if (payloadSize == 127)
        {
            auto extended = socket->readBytes(8, nullptr, nullptr, cancellation);
            if (!extended || extended->size() != 8)
            {
                return std::nullopt;
            }

            payloadSize = 0;
            for (char ch : *extended)
            {
                payloadSize = (payloadSize << 8) | static_cast<uint8_t>(ch);
            }
        }

        std::array<uint8_t, 4> maskingKey = {0, 0, 0, 0};
        if (masked)
        {
            auto maskBytes = socket->readBytes(4, nullptr, nullptr, cancellation);
            if (!maskBytes || maskBytes->size() != 4)
            {
                return std::nullopt;
            }

            for (size_t i = 0; i < 4; ++i)
            {
                maskingKey[i] = static_cast<uint8_t>((*maskBytes)[i]);
            }
        }

        auto payload = socket->readBytes(static_cast<size_t>(payloadSize), nullptr, nullptr, cancellation);
        if (!payload || payload->size() < 2)
        {
            return std::nullopt;
        }

        uint8_t code0 = static_cast<uint8_t>((*payload)[0]);
        uint8_t code1 = static_cast<uint8_t>((*payload)[1]);

        if (masked)
        {
            code0 ^= maskingKey[0];
            code1 ^= maskingKey[1];
        }

        uint16_t code = static_cast<uint16_t>((code0 << 8) | code1);
        return code;
    }

    std::string makeMaskedClientFrame(uint8_t opcode, const std::string& payload)
    {
        REQUIRE(payload.size() <= 125);

        std::string frame;
        std::array<uint8_t, 4> mask = {0x11, 0x22, 0x33, 0x44};

        frame.push_back(static_cast<char>(0x80 | opcode));
        frame.push_back(static_cast<char>(0x80 | payload.size()));
        for (uint8_t byte : mask)
        {
            frame.push_back(static_cast<char>(byte));
        }

        for (size_t i = 0; i < payload.size(); ++i)
        {
            frame.push_back(static_cast<char>(static_cast<uint8_t>(payload[i]) ^ mask[i & 0x3]));
        }

        return frame;
    }

    template<typename Predicate>
    void waitUntil(Predicate predicate, int attempts = 100)
    {
        for (int i = 0; i < attempts && !predicate(); ++i)
        {
            ix::msleep(10);
        }
    }
} // namespace ix

TEST_CASE("SocketServer", "[socket_server]")
{
    SECTION("maxConnections counts active connection threads")
    {
        int port = getFreePort();
        MaxConnectionSocketServer server(port);

        auto err = server.listen();
        if (err) INFO(*err);
        REQUIRE(!err);
        server.start();

        auto firstSocket = connectRawSocket(port);
        waitUntil([&server] { return server.handledConnections.load() != 0; });
        const bool firstConnectionHandled = server.handledConnections.load() == 1;

        std::string errMsg;
        bool tls = false;
        SocketTLSOptions tlsOptions;
        auto secondSocket = createSocket(tls, -1, errMsg, tlsOptions);
        std::string host("127.0.0.1");
        if (firstConnectionHandled)
        {
            secondSocket->connect(host, port, errMsg, neverCancel);

            waitUntil([&server] { return server.handledConnections.load() >= 2; });
        }
        const size_t handledConnections = server.handledConnections.load();

        firstSocket->close();
        secondSocket->close();
        server.releaseConnections = true;
        server.stop();

        REQUIRE(firstConnectionHandled);
        REQUIRE(handledConnections == 1);
    }
}

TEST_CASE("Websocket_server", "[websocket_server]")
{
    SECTION("Server handshake reports the switching-protocol status")
    {
        std::stringstream request;
        request << "GET / HTTP/1.1\r\n";
        request << "Host: 127.0.0.1\r\n";
        request << "Upgrade: websocket\r\n";
        request << "Connection: Upgrade\r\n";
        request << "Sec-WebSocket-Version: 13\r\n";
        request << "Sec-WebSocket-Key: " << kValidSecWebSocketKey << "\r\n";
        request << "\r\n";

        auto socket = std::make_unique<ScriptedSocket>(request.str());
        WebSocketTransport transport;
        transport.configure(WebSocketPerMessageDeflateOptions(),
                            SocketTLSOptions(),
                            ProxyConfig(),
                            true,
                            0);
        auto status = transport.connectToSocket(std::move(socket), 3, false);

        REQUIRE(status.success);
        REQUIRE(status.http_status == 101);
        transport.close();
    }

    SECTION("Connect to the server, do not send anything. Should timeout and return 400")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        server.setHandshakeTimeoutSecs(5);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);

        auto lineResult = socket->readLine(neverCancel);
        REQUIRE(lineResult.has_value());

        auto line = *lineResult;

        int status = -1;
        REQUIRE(sscanf(line.c_str(), "HTTP/1.1 %d", &status) == 1);
        REQUIRE(status == 400);

        // Give us 500ms for the server to notice that clients went away
        ix::msleep(500);
        server.stop();
        REQUIRE(server.getClients().size() == 0);
    }

    SECTION("Connect to the server. Send GET request without header. Should return 400")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);

        TLogger() << "writeBytes";
        socket->writeBytes("GET /\r\n", neverCancel);

        auto lineResult = socket->readLine(neverCancel);
        REQUIRE(lineResult.has_value());

        auto line = *lineResult;

        int status = -1;
        REQUIRE(sscanf(line.c_str(), "HTTP/1.1 %d", &status) == 1);
        REQUIRE(status == 400);

        // Give us 500ms for the server to notice that clients went away
        ix::msleep(500);
        server.stop();
        REQUIRE(server.getClients().size() == 0);
    }

    SECTION("Connect to the server. Missing Connection upgrade token should return 400")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(socket, "127.0.0.1", port, "", 400);

        ix::msleep(200);
        server.stop();
        REQUIRE(server.getClients().size() == 0);
    }

    SECTION("Connect to the server. Invalid Sec-WebSocket-Key should return 400")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(
            socket, "127.0.0.1", port, "Connection: Upgrade\r\n", 400, "foobar");

        ix::msleep(200);
        server.stop();
        REQUIRE(server.getClients().size() == 0);
    }

    SECTION("Connect to the server. Invalid Sec-WebSocket-Version should return 400")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(socket,
                                      "127.0.0.1",
                                      port,
                                      "Connection: Upgrade\r\n",
                                      400,
                                      kValidSecWebSocketKey,
                                      "invalid");
        readHeadersUntilBlankLine(socket);

        ix::msleep(200);
        server.stop();
        REQUIRE(server.getClients().size() == 0);
    }

    SECTION("Connect to the server with tokenized Connection header. Should return 101")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(
            socket, "127.0.0.1", port, "Connection: keep-alive, Upgrade\r\n", 101);

        socket->close();
        ix::msleep(200);

        server.stop();
        REQUIRE(connectionId == "foobarConnectionId");
        REQUIRE(server.getClients().size() == 0);
    }

    SECTION("Connect to the server. Send GET request with correct header")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);

        socket->writeBytes("GET / HTTP/1.1\r\n"
                           "Connection: Upgrade\r\n"
                           "Upgrade: websocket\r\n"
                           "Sec-WebSocket-Version: 13\r\n"
                           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                           "\r\n",
                           neverCancel);

        auto lineResult = socket->readLine(neverCancel);
        REQUIRE(lineResult.has_value());

        auto line = *lineResult;

        int status = -1;
        REQUIRE(sscanf(line.c_str(), "HTTP/1.1 %d", &status) == 1);
        REQUIRE(status == 101);

        while (true)
        {
            auto headerLine = socket->readLine(neverCancel);
            REQUIRE(headerLine.has_value());
            if (*headerLine == "\r\n") break;
        }

        socket->close();

        // Give us 500ms for the server to notice that clients went away
        ix::msleep(500);

        server.stop();
        REQUIRE(connectionId == "foobarConnectionId");
        REQUIRE(server.getClients().size() == 0);
    }

    SECTION("Server rejects unmasked client data frames with protocol error")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(
            socket, "127.0.0.1", port, "Connection: Upgrade\r\n", 101);

        std::string frame;
        frame.push_back(static_cast<char>(0x81)); // FIN + text
        frame.push_back(static_cast<char>(0x02)); // unmasked payload len 2
        frame += "hi";
        REQUIRE(socket->writeBytes(frame, neverCancel));

        auto closeCode = readCloseCode(socket, 3);
        REQUIRE(closeCode.has_value());
        REQUIRE(*closeCode == WebSocketCloseConstants::kProtocolErrorCode);

        socket->close();
        ix::msleep(200);
        server.stop();
    }

    SECTION("Server rejects non-minimal 16-bit payload length encoding")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(
            socket, "127.0.0.1", port, "Connection: Upgrade\r\n", 101);

        std::string frame;
        frame.push_back(static_cast<char>(0x81)); // FIN + text
        frame.push_back(static_cast<char>(0xfe)); // masked + 16-bit payload length
        frame.push_back(static_cast<char>(0x00));
        frame.push_back(static_cast<char>(0x02)); // length 2 must use the 7-bit form
        frame.push_back(static_cast<char>(0x01));
        frame.push_back(static_cast<char>(0x02));
        frame.push_back(static_cast<char>(0x03));
        frame.push_back(static_cast<char>(0x04));
        frame.push_back(static_cast<char>('h' ^ 0x01));
        frame.push_back(static_cast<char>('i' ^ 0x02));
        REQUIRE(socket->writeBytes(frame, neverCancel));

        auto closeCode = readCloseCode(socket, 3);
        REQUIRE(closeCode.has_value());
        REQUIRE(*closeCode == WebSocketCloseConstants::kProtocolErrorCode);

        socket->close();
        ix::msleep(200);
        server.stop();
    }

    SECTION("Server rejects 64-bit payload length with high bit set")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(
            socket, "127.0.0.1", port, "Connection: Upgrade\r\n", 101);

        std::string frame;
        frame.push_back(static_cast<char>(0x81)); // FIN + text
        frame.push_back(static_cast<char>(0xff)); // masked + 64-bit payload length
        frame.push_back(static_cast<char>(0x80)); // most significant length bit is reserved
        for (size_t i = 0; i < 7; ++i)
        {
            frame.push_back(static_cast<char>(0x00));
        }
        frame.push_back(static_cast<char>(0x01));
        frame.push_back(static_cast<char>(0x02));
        frame.push_back(static_cast<char>(0x03));
        frame.push_back(static_cast<char>(0x04));
        REQUIRE(socket->writeBytes(frame, neverCancel));

        auto closeCode = readCloseCode(socket, 3);
        REQUIRE(closeCode.has_value());
        REQUIRE(*closeCode == WebSocketCloseConstants::kProtocolErrorCode);

        socket->close();
        ix::msleep(200);
        server.stop();
    }

    SECTION("Server rejects non-minimal 64-bit payload length encoding")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(
            socket, "127.0.0.1", port, "Connection: Upgrade\r\n", 101);

        std::string frame;
        frame.push_back(static_cast<char>(0x81)); // FIN + text
        frame.push_back(static_cast<char>(0xff)); // masked + 64-bit payload length
        for (size_t i = 0; i < 7; ++i)
        {
            frame.push_back(static_cast<char>(0x00));
        }
        frame.push_back(static_cast<char>(0x02)); // length 2 must use the 7-bit form
        frame.push_back(static_cast<char>(0x01));
        frame.push_back(static_cast<char>(0x02));
        frame.push_back(static_cast<char>(0x03));
        frame.push_back(static_cast<char>(0x04));
        frame.push_back(static_cast<char>('h' ^ 0x01));
        frame.push_back(static_cast<char>('i' ^ 0x02));
        REQUIRE(socket->writeBytes(frame, neverCancel));

        auto closeCode = readCloseCode(socket, 3);
        REQUIRE(closeCode.has_value());
        REQUIRE(*closeCode == WebSocketCloseConstants::kProtocolErrorCode);

        socket->close();
        ix::msleep(200);
        server.stop();
    }

    SECTION("Server rejects CLOSE frames with payload length 1")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(
            socket, "127.0.0.1", port, "Connection: Upgrade\r\n", 101);

        std::string frame;
        frame.push_back(static_cast<char>(0x88)); // FIN + close
        frame.push_back(static_cast<char>(0x81)); // masked + payload len 1
        frame.push_back(static_cast<char>(0x01));
        frame.push_back(static_cast<char>(0x02));
        frame.push_back(static_cast<char>(0x03));
        frame.push_back(static_cast<char>(0x04));
        frame.push_back(static_cast<char>(0x7f ^ 0x01));
        REQUIRE(socket->writeBytes(frame, neverCancel));

        auto closeCode = readCloseCode(socket, 3);
        REQUIRE(closeCode.has_value());
        REQUIRE(*closeCode == WebSocketCloseConstants::kProtocolErrorCode);

        socket->close();
        ix::msleep(200);
        server.stop();
    }

    SECTION("Server rejects reserved CLOSE code 1015")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::string connectionId;
        REQUIRE(startServer(server, connectionId));

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(
            socket, "127.0.0.1", port, "Connection: Upgrade\r\n", 101);

        std::string closePayload;
        closePayload.push_back(static_cast<char>(0x03));
        closePayload.push_back(static_cast<char>(0xf7));
        REQUIRE(socket->writeBytes(makeMaskedClientFrame(0x8, closePayload), neverCancel));

        auto closeCode = readCloseCode(socket, 3);
        REQUIRE(closeCode.has_value());
        REQUIRE(*closeCode == WebSocketCloseConstants::kProtocolErrorCode);

        socket->close();
        ix::msleep(200);
        server.stop();
    }

    SECTION("Server ignores data frames queued after a CLOSE frame")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<int> messagesReceived(0);

        server.setOnClientMessageCallback([&messagesReceived](std::shared_ptr<ConnectionState>,
                                                              WebSocket&,
                                                              const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Message)
            {
                ++messagesReceived;
            }
        });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        auto socket = connectRawSocket(port);
        sendHandshakeAndRequireStatus(
            socket, "127.0.0.1", port, "Connection: Upgrade\r\n", 101);

        std::string closePayload;
        closePayload.push_back(static_cast<char>(0x03));
        closePayload.push_back(static_cast<char>(0xe8));

        std::string frames = makeMaskedClientFrame(0x8, closePayload);
        frames += makeMaskedClientFrame(0x1, "after-close");
        REQUIRE(socket->writeBytes(frames, neverCancel));

        auto closeCode = readCloseCode(socket, 3);
        REQUIRE(closeCode.has_value());
        REQUIRE(*closeCode == WebSocketCloseConstants::kNormalClosureCode);

        ix::msleep(200);
        socket->close();
        server.stop();

        REQUIRE(messagesReceived.load() == 0);
    }

    SECTION("Client accepts tokenized Connection header from server handshake")
    {
        int port = getFreePort();
        ScriptedHandshakeServer server(port, "keep-alive, Upgrade");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        ix::WebSocket webSocket;
        webSocket.setOnMessageCallback([](const ix::WebSocketMessagePtr&) {});

        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port;
        webSocket.setUrl(ss.str());

        auto result = webSocket.connect(3);
        REQUIRE(result.success);

        webSocket.stop();
        server.stop();
    }

    SECTION("Client follows query-only redirect without duplicating original query")
    {
        int port = getFreePort();
        QueryRedirectHandshakeServer server(port);

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        ix::WebSocket webSocket;
        webSocket.setOnMessageCallback([](const ix::WebSocketMessagePtr&) {});

        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port << "/redirect?old=1";
        webSocket.setUrl(ss.str());

        auto result = webSocket.connect(3);
        REQUIRE(result.success);

        webSocket.stop();
        server.stop();
    }

    SECTION("Client clears fragmented receive state before reconnecting")
    {
        int port = getFreePort();
        TwoConnectionFrameServer server(port);

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        ix::WebSocket webSocket;
        webSocket.setAutomaticReconnection(true);
        webSocket.setMinWaitBetweenReconnectionRetries(1);
        webSocket.setMaxWaitBetweenReconnectionRetries(1);

        std::atomic<bool> gotStaleMessage(false);
        std::atomic<bool> gotProtocolClose(false);
        webSocket.setOnMessageCallback([&gotStaleMessage, &gotProtocolClose](
                                           const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Message && msg->str == "stale-data")
            {
                gotStaleMessage = true;
            }
            else if (msg->type == ix::WebSocketMessageType::Close &&
                     msg->closeInfo.code == WebSocketCloseConstants::kProtocolErrorCode)
            {
                gotProtocolClose = true;
            }
        });

        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port;
        webSocket.setUrl(ss.str());
        webSocket.start();

        waitUntil([&gotProtocolClose] { return gotProtocolClose.load(); }, 300);

        webSocket.stop();
        server.stop();

        REQUIRE(server.firstConnectionHandled.load());
        REQUIRE(server.secondConnectionHandled.load());
        REQUIRE(gotProtocolClose.load());
        REQUIRE_FALSE(gotStaleMessage.load());
    }

    SECTION("Client can stop from its message callback without self-joining")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);

        server.setOnClientMessageCallback([](std::shared_ptr<ConnectionState>,
                                             WebSocket& webSocket,
                                             const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Open)
            {
                webSocket.send("stop from callback");
            }
        });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        {
            ix::WebSocket webSocket;
            std::atomic<bool> stoppedInCallback(false);
            webSocket.setOnMessageCallback([&webSocket, &stoppedInCallback](
                                               const ix::WebSocketMessagePtr& msg) {
                if (msg->type == ix::WebSocketMessageType::Message)
                {
                    webSocket.stop();
                    stoppedInCallback = true;
                }
            });

            std::stringstream ss;
            ss << "ws://127.0.0.1:" << port;
            webSocket.setUrl(ss.str());
            webSocket.start();

            waitUntil([&stoppedInCallback] { return stoppedInCallback.load(); });

            REQUIRE(stoppedInCallback);

            waitUntil([&webSocket] { return webSocket.getReadyState() == ix::ReadyState::Closed; });
        }
        server.stop();
    }

    SECTION("Server can stop from its message callback without deadlocking")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<bool> stopReturned(false);

        server.setOnClientMessageCallback([&server, &stopReturned](
                                             std::shared_ptr<ConnectionState>,
                                             WebSocket&,
                                             const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Message)
            {
                server.stop();
                stopReturned = true;
            }
        });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        ix::WebSocket webSocket;
        webSocket.setOnMessageCallback([](const ix::WebSocketMessagePtr&) {});

        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port;
        webSocket.setUrl(ss.str());

        auto result = webSocket.connect(3);
        REQUIRE(result.success);

        auto sendInfo = webSocket.send("stop server");
        REQUIRE(sendInfo.success);

        waitUntil([&stopReturned] { return stopReturned.load(); });

        REQUIRE(stopReturned);
        webSocket.stop();
        server.stop();
    }

    SECTION("Server websocket can stop itself from its message callback without deadlocking")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<bool> stopReturned(false);

        server.setOnClientMessageCallback([&stopReturned](std::shared_ptr<ConnectionState>,
                                                          WebSocket& serverWebSocket,
                                                          const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Message)
            {
                serverWebSocket.stop();
                stopReturned = true;
            }
        });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        ix::WebSocket webSocket;
        webSocket.setOnMessageCallback([](const ix::WebSocketMessagePtr&) {});

        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port;
        webSocket.setUrl(ss.str());

        auto result = webSocket.connect(3);
        REQUIRE(result.success);

        auto sendInfo = webSocket.send("stop websocket");
        REQUIRE(sendInfo.success);

        waitUntil([&stopReturned] { return stopReturned.load(); });

        REQUIRE(stopReturned);
        webSocket.stop();
        server.stop();
    }

    SECTION("Client message callback exceptions do not terminate worker thread")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);

        server.setOnClientMessageCallback([](std::shared_ptr<ConnectionState>,
                                             WebSocket& webSocket,
                                             const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Open)
            {
                webSocket.send("callback throws");
            }
        });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        ix::WebSocket webSocket;
        std::atomic<bool> threwInCallback(false);
        webSocket.setOnMessageCallback([&threwInCallback](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Message)
            {
                threwInCallback = true;
                throw std::runtime_error("callback failure");
            }
        });

        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port;
        webSocket.setUrl(ss.str());
        webSocket.start();

        waitUntil([&threwInCallback] { return threwInCallback.load(); });

        REQUIRE(threwInCallback);
        webSocket.stop();
        server.stop();
    }

    SECTION("Client can send empty text message")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        std::atomic<bool> receivedEmptyMessage(false);

        server.setOnClientMessageCallback([&receivedEmptyMessage](std::shared_ptr<ConnectionState>,
                                                                  WebSocket&,
                                                                  const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Message && msg->str.empty() && !msg->binary)
            {
                receivedEmptyMessage = true;
            }
        });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        ix::WebSocket webSocket;
        webSocket.setOnMessageCallback([](const ix::WebSocketMessagePtr&) {});

        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port;
        webSocket.setUrl(ss.str());

        auto result = webSocket.connect(3);
        REQUIRE(result.success);

        auto sendInfo = webSocket.send("");
        REQUIRE(sendInfo.success);

        waitUntil([&receivedEmptyMessage] { return receivedEmptyMessage.load(); });

        REQUIRE(receivedEmptyMessage);
        webSocket.stop();
        server.stop();
    }

    SECTION("Client can send fragmented text message with a non-aligned final fragment")
    {
        int port = getFreePort();
        ix::WebSocketServer server(port);
        const std::string payload((1 << 15) + 17, 'x');
        std::atomic<bool> receivedPayload(false);

        server.setOnClientMessageCallback([&payload, &receivedPayload](
                                              std::shared_ptr<ConnectionState>,
                                              WebSocket&,
                                              const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Message && msg->str == payload)
            {
                receivedPayload = true;
            }
        });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        ix::WebSocket webSocket;
        webSocket.setPerMessageDeflate(false);
        webSocket.setOnMessageCallback([](const ix::WebSocketMessagePtr&) {});

        std::stringstream ss;
        ss << "ws://127.0.0.1:" << port;
        webSocket.setUrl(ss.str());

        auto result = webSocket.connect(3);
        REQUIRE(result.success);

        auto sendInfo = webSocket.send(payload);
        REQUIRE(sendInfo.success);

        waitUntil([&receivedPayload] { return receivedPayload.load(); });

        REQUIRE(receivedPayload);
        webSocket.stop();
        server.stop();
    }
}
