/*
 *  IXSocketTest.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone. All rights reserved.
 */

#include "IXTest.h"
#include "catch.hpp"
#include <iostream>
#include <ixwebsocket/IXCancellationRequest.h>
#include <ixwebsocket/IXHttpServer.h>
#include <ixwebsocket/IXSocket.h>
#include <ixwebsocket/IXSocketFactory.h>
#include <ixwebsocket/IXUdpSocket.h>
#include <limits>
#include <string.h>

#ifndef _WIN32
#include <sys/socket.h>
#endif

using namespace ix;

namespace ix
{
    void testSocket(const std::string& host,
                    int port,
                    const std::string& request,
                    std::shared_ptr<Socket> socket,
                    int expectedStatus,
                    int timeoutSecs)
    {
        std::string errMsg;
        static std::atomic<bool> requestInitCancellation(false);
        auto isCancellationRequested =
            makeCancellationRequestWithTimeout(timeoutSecs, requestInitCancellation);

        bool success = socket->connect(host, port, errMsg, isCancellationRequested);
        TLogger() << "errMsg: " << errMsg;
        REQUIRE(success);

        TLogger() << "Sending request: " << request << "to " << host << ":" << port;
        REQUIRE(socket->writeBytes(request, isCancellationRequested));

        auto lineResult = socket->readLine(isCancellationRequested);

        TLogger() << "read error: " << strerror(Socket::getErrno());

        REQUIRE(lineResult.has_value());
        auto line = *lineResult;

        int status = -1;
        REQUIRE(sscanf(line.c_str(), "HTTP/1.1 %d", &status) == 1);
        REQUIRE(status == expectedStatus);
    }
} // namespace ix

TEST_CASE("socket", "[socket]")
{
    SECTION("Connect to a local websocket server over a free port. Send GET request without "
            "header. Should return 400")
    {
        // Start a server first which we'll hit with our socket code
        int port = getFreePort();
        ix::WebSocketServer server(port);
        REQUIRE(startWebSocketEchoServer(server));

        std::string errMsg;
        bool tls = false;
        SocketTLSOptions tlsOptions;
        std::shared_ptr<Socket> socket = createSocket(tls, -1, errMsg, tlsOptions);
        std::string host("127.0.0.1");

        std::stringstream ss;
        ss << "GET / HTTP/1.1\r\n";
        ss << "Host: " << host << "\r\n";
        ss << "\r\n";
        std::string request(ss.str());

        int expectedStatus = 400;
        int timeoutSecs = 3;

        testSocket(host, port, request, socket, expectedStatus, timeoutSecs);
    }

#if defined(IXWEBSOCKET_USE_TLS)
    SECTION("Connect to a local HTTPS server over a free port. Send GET request. Should return 200")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");

        SocketTLSOptions serverTlsOptions;
        serverTlsOptions.tls = true;
        serverTlsOptions.caFile = "NONE";
        serverTlsOptions.certFile = ".certs/trusted-localhost-server-crt.pem";
        serverTlsOptions.keyFile = ".certs/trusted-localhost-server-key.pem";
        serverTlsOptions.ciphers = "ALL:@SECLEVEL=0";
        server.setTLSOptions(serverTlsOptions);

        server.setOnConnectionCallback(
            [](HttpRequestPtr, std::shared_ptr<ConnectionState>) -> HttpResponsePtr {
                return std::make_shared<HttpResponse>(
                    200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), "ok");
            });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        std::string errMsg;
        bool tls = true;
        SocketTLSOptions tlsOptions;
        tlsOptions.caFile = ".certs/trusted-ca-crt.pem";
        tlsOptions.disable_hostname_validation = false;
        tlsOptions.ciphers = "ALL:@SECLEVEL=0";
        std::shared_ptr<Socket> socket = createSocket(tls, -1, errMsg, tlsOptions);
        std::string host("localhost");
        std::string request("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        int expectedStatus = 200;
        int timeoutSecs = 3;

        testSocket(host, port, request, socket, expectedStatus, timeoutSecs);

        server.stop();
    }
#endif

    SECTION("Connect closes an existing plain socket before replacing it")
    {
#ifdef _WIN32
        SUCCEED("socketpair-based socket replacement test is skipped on Windows");
#else
        int fds[2] = {-1, -1};
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

        Socket socket(fds[0]);
        std::string errMsg;
        auto isCancellationRequested = []() { return true; };

        REQUIRE_FALSE(socket.connect("127.0.0.1", 1, errMsg, isCancellationRequested));
        REQUIRE(socket.getFd() == -1);

        char byte = '\0';
        REQUIRE(::recv(fds[1], &byte, sizeof(byte), 0) == 0);
        Socket::closeSocket(fds[1]);
#endif
    }

    SECTION("readBytes rejects impossible aggregation sizes")
    {
        Socket socket(-1);
        auto isCancellationRequested = []() { return true; };
        auto result = socket.readBytes(
            std::numeric_limits<size_t>::max(), nullptr, nullptr, isCancellationRequested);

        REQUIRE_FALSE(result.has_value());
    }

    SECTION("UDP init closes an existing socket before resolving a new target")
    {
#ifdef _WIN32
        SUCCEED("fd-based UDP socket replacement test is skipped on Windows");
#else
        int fds[2] = {-1, -1};
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

        UdpSocket udpSocket(fds[0]);
        std::string errMsg;
        REQUIRE_FALSE(udpSocket.init("invalid host name", getFreePort(), errMsg));

        char byte = '\0';
        REQUIRE(::recv(fds[1], &byte, sizeof(byte), 0) == 0);
        Socket::closeSocket(fds[1]);
#endif
    }

    SECTION("UDP init rejects invalid target ports")
    {
        UdpSocket udpSocket;
        const int invalidPorts[] = {-1, 0, 70000};

        for (int port : invalidPorts)
        {
            std::string errMsg;
            REQUIRE_FALSE(udpSocket.init("127.0.0.1", port, errMsg));
            REQUIRE(errMsg == "Invalid UDP target port");
        }
    }

    SECTION("UDP sendto accepts zero-length datagrams")
    {
#ifdef _WIN32
        SUCCEED("UDP zero-length datagram test is skipped on Windows");
#else
        int serverFd = ::socket(AF_INET, SOCK_DGRAM, 0);
        REQUIRE(serverFd >= 0);

        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        serverAddress.sin_port = 0;

        REQUIRE(::bind(serverFd,
                       reinterpret_cast<struct sockaddr*>(&serverAddress),
                       sizeof(serverAddress)) == 0);

        socklen_t serverAddressLen = sizeof(serverAddress);
        REQUIRE(::getsockname(serverFd,
                              reinterpret_cast<struct sockaddr*>(&serverAddress),
                              &serverAddressLen) == 0);

        UdpSocket udpSocket;
        std::string errMsg;
        REQUIRE(udpSocket.init("127.0.0.1", ntohs(serverAddress.sin_port), errMsg));

        IoResult sent = udpSocket.sendto(std::string());
        REQUIRE(sent);
        REQUIRE(sent.bytes == 0);

        struct pollfd pfd;
        pfd.fd = serverFd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        REQUIRE(ix::poll(&pfd, 1, 1000, nullptr) > 0);

        char byte = '\0';
        sockaddr_storage peerAddress{};
        socklen_t peerAddressLen = sizeof(peerAddress);
        auto received = ::recvfrom(serverFd,
                                   &byte,
                                   sizeof(byte),
                                   0,
                                   reinterpret_cast<struct sockaddr*>(&peerAddress),
                                   &peerAddressLen);
        REQUIRE(received == 0);

        Socket::closeSocket(serverFd);
#endif
    }
}
