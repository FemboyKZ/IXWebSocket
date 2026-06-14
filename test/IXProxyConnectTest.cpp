/*
 *  IXProxyConnectTest.cpp
 *  Author: IXWebSocket contributors
 *  Copyright (c) 2026 Machine Zone. All rights reserved.
 */

#include "catch.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ixwebsocket/IXConnectionState.h>
#include <ixwebsocket/IXGetFreePort.h>
#include <ixwebsocket/IXHttpClient.h>
#include <ixwebsocket/IXHttpServer.h>
#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXProxyConnect.h>
#include <ixwebsocket/IXSocketConnect.h>
#include <ixwebsocket/IXSocketFactory.h>
#include <ixwebsocket/IXSocketServer.h>
#include <ixwebsocket/IXSocketTLSOptions.h>
#include <mutex>
#include <thread>

using namespace ix;

namespace
{
    bool neverCancel()
    {
        return false;
    }

    CancellationRequest makeTimeoutCancellation(int timeoutMs)
    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        return [deadline]() { return std::chrono::steady_clock::now() >= deadline; };
    }

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

        const std::string& writtenData() const
        {
            return _writtenData;
        }

    private:
        std::string _scriptedReadData;
        std::string _writtenData;
        size_t _readOffset = 0;
    };

    bool waitFd(int fd, short events, int timeoutMs)
    {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = events;
        pfd.revents = 0;

        return ix::poll(&pfd, 1, timeoutMs, nullptr) > 0;
    }

    bool recvAllFromFd(int fd, void* buffer, size_t length, int timeoutMs)
    {
        auto* data = static_cast<uint8_t*>(buffer);
        size_t offset = 0;

        while (offset < length)
        {
            auto ret = ::recv(fd, reinterpret_cast<char*>(data + offset), length - offset, 0);
            if (ret > 0)
            {
                offset += static_cast<size_t>(ret);
                continue;
            }

            if (ret < 0 && Socket::isWaitNeeded())
            {
                if (!waitFd(fd, POLLIN, timeoutMs))
                {
                    return false;
                }
                continue;
            }

            return false;
        }

        return true;
    }

    bool sendAllToFd(int fd, const void* buffer, size_t length, int timeoutMs)
    {
        auto* data = static_cast<const uint8_t*>(buffer);
        size_t offset = 0;

        while (offset < length)
        {
            auto ret = ::send(fd, reinterpret_cast<const char*>(data + offset), length - offset, 0);
            if (ret > 0)
            {
                offset += static_cast<size_t>(ret);
                continue;
            }

            if (ret < 0 && Socket::isWaitNeeded())
            {
                if (!waitFd(fd, POLLOUT, timeoutMs))
                {
                    return false;
                }
                continue;
            }

            return false;
        }

        return true;
    }

    class ConnectProxyServer final : public SocketServer
    {
    public:
        ConnectProxyServer(int port,
                           bool tls,
                           bool requireAuthentication,
                           std::string certFile = ".certs/trusted-server-crt.pem",
                           std::string keyFile = ".certs/trusted-server-key.pem")
            : SocketServer(port, "127.0.0.1")
            , _requireAuthentication(requireAuthentication)
            , _certFile(std::move(certFile))
            , _keyFile(std::move(keyFile))
        {
            if (tls)
            {
                SocketTLSOptions tlsOptions;
                tlsOptions.tls = true;
                tlsOptions.caFile = "NONE";
                tlsOptions.certFile = _certFile;
                tlsOptions.keyFile = _keyFile;
                tlsOptions.ciphers = "ALL:@SECLEVEL=0";
                setTLSOptions(tlsOptions);
            }
        }

        int getConnectCount() const
        {
            return _connectCount;
        }

        int getEstablishedTunnelCount() const
        {
            return _establishedTunnelCount;
        }

        std::string getLastAuthorizationHeader() const
        {
            std::lock_guard<std::mutex> lock(_mutex);
            return _lastAuthorizationHeader;
        }

    private:
        static bool writeAll(Socket& socket, const std::string& data)
        {
            return socket.writeBytes(data, neverCancel);
        }

        static bool parseConnectTarget(const std::string& requestLine,
                                       std::string& host,
                                       int& port)
        {
            const std::string prefix = "CONNECT ";
            const std::string suffix = " HTTP/1.1\r\n";

            if (requestLine.rfind(prefix, 0) != 0 ||
                requestLine.size() <= prefix.size() + suffix.size() ||
                requestLine.substr(requestLine.size() - suffix.size()) != suffix)
            {
                return false;
            }

            std::string hostPort =
                requestLine.substr(prefix.size(), requestLine.size() - prefix.size() - suffix.size());
            auto delimiter = hostPort.rfind(':');
            if (delimiter == std::string::npos)
            {
                return false;
            }

            host = hostPort.substr(0, delimiter);
            if (host.empty()) return false;

            try
            {
                port = std::stoi(hostPort.substr(delimiter + 1));
            }
            catch (...)
            {
                return false;
            }

            return port > 0;
        }

        static void relay(Socket& source, Socket& destination, std::atomic<bool>& stop)
        {
            std::array<char, 1 << 14> buffer{};
            int idleTimeoutCounter = 0;

            while (!stop)
            {
                auto readReady = source.isReadyToRead(50);
                if (readReady == PollResultType::Timeout)
                {
                    if (++idleTimeoutCounter > 40)
                    {
                        break;
                    }
                    continue;
                }

                idleTimeoutCounter = 0;

                if (readReady == PollResultType::Error)
                {
                    break;
                }

                auto readResult = source.recv(buffer.data(), buffer.size());
                if (!readResult)
                {
                    if (readResult.wouldBlock())
                    {
                        continue;
                    }

                    break;
                }

                size_t offset = 0;
                while (offset < readResult.bytes && !stop)
                {
                    auto writeResult =
                        destination.send(buffer.data() + offset, readResult.bytes - offset);

                    if (writeResult)
                    {
                        offset += writeResult.bytes;
                        continue;
                    }

                    if (writeResult.wouldBlock())
                    {
                        if (destination.isReadyToWrite(50) == PollResultType::Error)
                        {
                            stop = true;
                        }
                        continue;
                    }

                    stop = true;
                }
            }

            stop = true;
            source.close();
            destination.close();
        }

        static void relayBidirectional(Socket& downstream, Socket& upstream)
        {
            std::atomic<bool> stop(false);

            std::thread upstreamThread([&] { relay(downstream, upstream, stop); });
            std::thread downstreamThread([&] { relay(upstream, downstream, stop); });

            upstreamThread.join();
            downstreamThread.join();
        }

        void handleConnection(std::unique_ptr<Socket> socket,
                              std::shared_ptr<ConnectionState> connectionState) final
        {
            struct ConnectionTerminator
            {
                explicit ConnectionTerminator(std::shared_ptr<ConnectionState> state)
                    : _state(std::move(state))
                {
                }

                ~ConnectionTerminator()
                {
                    if (_state)
                    {
                        _state->setTerminated();
                    }
                }

                std::shared_ptr<ConnectionState> _state;
            } terminator(connectionState);

            auto requestLine = socket->readLine(neverCancel);
            if (!requestLine)
            {
                socket->close();
                return;
            }

            std::string targetHost;
            int targetPort = 0;
            if (!parseConnectTarget(*requestLine, targetHost, targetPort))
            {
                writeAll(*socket, "HTTP/1.1 400 Bad Request\r\n\r\n");
                socket->close();
                return;
            }

            std::string authorizationHeader;
            while (true)
            {
                auto header = socket->readLine(neverCancel);
                if (!header)
                {
                    socket->close();
                    return;
                }

                if (*header == "\r\n")
                {
                    break;
                }

                const std::string authHeaderPrefix = "Proxy-Authorization: ";
                if (header->rfind(authHeaderPrefix, 0) == 0)
                {
                    authorizationHeader = header->substr(authHeaderPrefix.size());

                    if (authorizationHeader.size() >= 2 &&
                        authorizationHeader.substr(authorizationHeader.size() - 2) == "\r\n")
                    {
                        authorizationHeader.resize(authorizationHeader.size() - 2);
                    }
                }
            }

            {
                std::lock_guard<std::mutex> lock(_mutex);
                _lastAuthorizationHeader = authorizationHeader;
            }

            ++_connectCount;

            if (_requireAuthentication && authorizationHeader.empty())
            {
                writeAll(*socket,
                         "HTTP/1.1 407 Proxy Authentication Required\r\n"
                         "Proxy-Authenticate: Basic realm=\"ixproxy\"\r\n\r\n");
                socket->close();
                return;
            }

            std::string createSocketError;
            SocketTLSOptions tlsOptions;
            auto upstream = createSocket(false, -1, createSocketError, tlsOptions);
            if (!upstream)
            {
                writeAll(*socket, "HTTP/1.1 502 Bad Gateway\r\n\r\n");
                socket->close();
                return;
            }

            std::string connectError;
            if (!upstream->connect(targetHost, targetPort, connectError, neverCancel))
            {
                writeAll(*socket, "HTTP/1.1 502 Bad Gateway\r\n\r\n");
                socket->close();
                return;
            }

            if (!writeAll(*socket, "HTTP/1.1 200 Connection Established\r\n\r\n"))
            {
                upstream->close();
                socket->close();
                return;
            }

            ++_establishedTunnelCount;
            relayBidirectional(*socket, *upstream);
        }

        size_t getConnectedClientsCount() final
        {
            return 0;
        }

        bool _requireAuthentication;
        std::atomic<int> _connectCount{0};
        std::atomic<int> _establishedTunnelCount{0};

        mutable std::mutex _mutex;
        std::string _lastAuthorizationHeader;
        std::string _certFile;
        std::string _keyFile;
    };
} // namespace

TEST_CASE("proxy_connect", "[proxy]")
{
    SECTION("ProxyConfig rejects invalid manual ports")
    {
        ProxyConfig proxy;
        proxy.type = ProxyType::Http;
        proxy.host = "127.0.0.1";

        proxy.port = 0;
        REQUIRE_FALSE(proxy.isEnabled());

        proxy.port = 70000;
        REQUIRE_FALSE(proxy.isEnabled());

        proxy.port = 65535;
        REQUIRE(proxy.isEnabled());
    }

    SECTION("ProxyConfig fromUrl reports malformed URLs")
    {
        ProxyConfig proxy;
        std::string errorMsg;

        REQUIRE_FALSE(ProxyConfig::fromUrl("http://", proxy, &errorMsg));
        REQUIRE_FALSE(errorMsg.empty());
        REQUIRE_FALSE(proxy.isEnabled());
    }

    SECTION("ProxyConfig fromUrl reports unsupported schemes")
    {
        ProxyConfig proxy;
        std::string errorMsg;

        REQUIRE_FALSE(ProxyConfig::fromUrl("ftp://proxy.example:21", proxy, &errorMsg));
        REQUIRE(errorMsg == "Unsupported proxy URL scheme");
        REQUIRE_FALSE(proxy.isEnabled());
    }

    SECTION("ProxyConfig fromUrl keeps valid URL parsing")
    {
        ProxyConfig proxy;
        std::string errorMsg;

        REQUIRE(ProxyConfig::fromUrl("socks5://user:pass@proxy.example/", proxy, &errorMsg));
        REQUIRE(errorMsg.empty());
        REQUIRE(proxy.type == ProxyType::Socks5);
        REQUIRE(proxy.host == "proxy.example");
        REQUIRE(proxy.port == 1080);
        REQUIRE(proxy.username == "user");
        REQUIRE(proxy.password == "pass");
    }

    SECTION("CONNECT rejects invalid target ports")
    {
        ProxyConfig proxy;
        proxy.type = ProxyType::Http;

        const int invalidPorts[] = {-1, 0, 70000};
        for (int port : invalidPorts)
        {
            ScriptedSocket socket("");
            std::string errMsg;
            bool success = ProxyConnect::connect(socket, proxy, "example.org", port, errMsg, neverCancel);

            REQUIRE_FALSE(success);
            REQUIRE(errMsg == "Invalid proxy CONNECT target port");
            REQUIRE(socket.writtenData().empty());
        }
    }

    SECTION("CONNECT over pre-established stream supports HTTPS proxy type")
    {
        ProxyConfig proxy;
        proxy.type = ProxyType::Https;
        proxy.username = "user";
        proxy.password = "pass";

        ScriptedSocket socket(
            "HTTP/1.1 200 Connection Established\r\n"
            "X-Test: 1\r\n"
            "\r\n");

        std::string errMsg;
        bool success =
            ProxyConnect::connect(socket, proxy, "example.org", 443, errMsg, neverCancel);

        REQUIRE(success);
        REQUIRE(errMsg.empty());
        REQUIRE(socket.writtenData().find("CONNECT example.org:443 HTTP/1.1\r\n") !=
                std::string::npos);
        REQUIRE(socket.writtenData().find("Host: example.org:443\r\n") != std::string::npos);
        REQUIRE(socket.writtenData().find("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") !=
                std::string::npos);
    }

    SECTION("CONNECT rejects malformed HTTP proxy status code")
    {
        ProxyConfig proxy;
        proxy.type = ProxyType::Http;

        ScriptedSocket socket(
            "HTTP/1.1 20X Bad Status\r\n"
            "\r\n");

        std::string errMsg;
        bool success =
            ProxyConnect::connect(socket, proxy, "example.org", 443, errMsg, neverCancel);

        REQUIRE_FALSE(success);
        REQUIRE(errMsg.find("Invalid proxy response") != std::string::npos);
    }

    SECTION("CONNECT rejects missing delimiter after HTTP proxy status code")
    {
        ProxyConfig proxy;
        proxy.type = ProxyType::Http;

        ScriptedSocket socket(
            "HTTP/1.1 200OK\r\n"
            "\r\n");

        std::string errMsg;
        bool success =
            ProxyConnect::connect(socket, proxy, "example.org", 443, errMsg, neverCancel);

        REQUIRE_FALSE(success);
        REQUIRE(errMsg.find("Invalid proxy response") != std::string::npos);
    }

    SECTION("CONNECT rejects too many HTTP proxy response headers")
    {
        ProxyConfig proxy;
        proxy.type = ProxyType::Http;

        std::string response("HTTP/1.1 200 Connection Established\r\n");
        for (int i = 0; i < 101; ++i)
        {
            response += "X-Test: value\r\n";
        }
        response += "\r\n";

        ScriptedSocket socket(response);
        std::string errMsg;
        bool success =
            ProxyConnect::connect(socket, proxy, "example.org", 443, errMsg, neverCancel);

        REQUIRE_FALSE(success);
        REQUIRE(errMsg == "Proxy response has too many headers");
    }

    SECTION("CONNECT rejects oversized HTTP proxy response headers")
    {
        ProxyConfig proxy;
        proxy.type = ProxyType::Http;

        std::string response("HTTP/1.1 200 Connection Established\r\n");
        for (int i = 0; i < 10; ++i)
        {
            response += "X-Test: ";
            response.append(7000, 'a');
            response += "\r\n";
        }
        response += "\r\n";

        ScriptedSocket socket(response);
        std::string errMsg;
        bool success =
            ProxyConnect::connect(socket, proxy, "example.org", 443, errMsg, neverCancel);

        REQUIRE_FALSE(success);
        REQUIRE(errMsg == "Proxy response headers are too large");
    }

    SECTION("HTTPS proxy is rejected on raw fd path")
    {
        ProxyConfig proxy;
        proxy.type = ProxyType::Https;

        std::string errMsg;
        bool success =
            ProxyConnect::connect(-1, proxy, "example.org", 443, errMsg, neverCancel);

        REQUIRE_FALSE(success);
        REQUIRE(errMsg.find("TLS stream") != std::string::npos);
    }

    SECTION("SOCKS5 is rejected on pre-established stream")
    {
        ProxyConfig proxy;
        proxy.type = ProxyType::Socks5;

        ScriptedSocket socket("");
        std::string errMsg;
        bool success = ProxyConnect::connect(socket, proxy, "example.org", 443, errMsg, neverCancel);

        REQUIRE_FALSE(success);
        REQUIRE(errMsg == "SOCKS5 is not supported on pre-established proxy streams");
    }

    SECTION("SOCKS5 rejects unsupported auth methods")
    {
#ifdef _WIN32
        SUCCEED("socketpair-based SOCKS5 test is skipped on Windows");
#else
        int fds[2] = {-1, -1};
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        SocketConnect::configureSocket(fds[0]);
        SocketConnect::configureSocket(fds[1]);

        std::atomic<bool> serverScriptOk(true);
        std::thread scriptedProxy([&]() {
            uint8_t greeting[3]{};
            if (!recvAllFromFd(fds[1], greeting, sizeof(greeting), 1000) || greeting[0] != 0x05)
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            const uint8_t response[2] = {0x05, 0x7f};
            if (!sendAllToFd(fds[1], response, sizeof(response), 1000))
            {
                serverScriptOk = false;
            }

            Socket::closeSocket(fds[1]);
        });

        ProxyConfig proxy;
        proxy.type = ProxyType::Socks5;

        std::string errMsg;
        bool success = ProxyConnect::connect(
            fds[0], proxy, "example.org", 443, errMsg, makeTimeoutCancellation(3000));

        Socket::closeSocket(fds[0]);
        scriptedProxy.join();

        REQUIRE(serverScriptOk.load());
        REQUIRE_FALSE(success);
        REQUIRE(errMsg == "SOCKS5 server selected unsupported auth method");
#endif
    }

    SECTION("SOCKS5 rejects invalid username-password auth version")
    {
#ifdef _WIN32
        SUCCEED("socketpair-based SOCKS5 test is skipped on Windows");
#else
        int fds[2] = {-1, -1};
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        SocketConnect::configureSocket(fds[0]);
        SocketConnect::configureSocket(fds[1]);

        std::atomic<bool> serverScriptOk(true);
        std::thread scriptedProxy([&]() {
            uint8_t greeting[4]{};
            if (!recvAllFromFd(fds[1], greeting, sizeof(greeting), 1000) || greeting[0] != 0x05 ||
                greeting[1] != 0x02)
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            const uint8_t methodSelection[2] = {0x05, 0x02};
            if (!sendAllToFd(fds[1], methodSelection, sizeof(methodSelection), 1000))
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            uint8_t authRequest[5]{};
            if (!recvAllFromFd(fds[1], authRequest, sizeof(authRequest), 1000) ||
                authRequest[0] != 0x01)
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            const uint8_t authResponse[2] = {0x02, 0x00};
            if (!sendAllToFd(fds[1], authResponse, sizeof(authResponse), 1000))
            {
                serverScriptOk = false;
            }

            Socket::closeSocket(fds[1]);
        });

        ProxyConfig proxy;
        proxy.type = ProxyType::Socks5;
        proxy.username = "u";
        proxy.password = "p";

        std::string errMsg;
        bool success = ProxyConnect::connect(
            fds[0], proxy, "example.org", 443, errMsg, makeTimeoutCancellation(3000));

        Socket::closeSocket(fds[0]);
        scriptedProxy.join();

        REQUIRE(serverScriptOk.load());
        REQUIRE_FALSE(success);
        REQUIRE(errMsg == "Invalid SOCKS5 auth version in response");
#endif
    }

    SECTION("SOCKS5 rejects non-zero reserved byte in connect response")
    {
#ifdef _WIN32
        SUCCEED("socketpair-based SOCKS5 test is skipped on Windows");
#else
        int fds[2] = {-1, -1};
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        SocketConnect::configureSocket(fds[0]);
        SocketConnect::configureSocket(fds[1]);

        std::atomic<bool> serverScriptOk(true);
        std::thread scriptedProxy([&]() {
            uint8_t greeting[3]{};
            if (!recvAllFromFd(fds[1], greeting, sizeof(greeting), 1000) || greeting[0] != 0x05)
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            const uint8_t methodSelection[2] = {0x05, 0x00};
            if (!sendAllToFd(fds[1], methodSelection, sizeof(methodSelection), 1000))
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            uint8_t connectPrefix[5]{};
            if (!recvAllFromFd(fds[1], connectPrefix, sizeof(connectPrefix), 1000) ||
                connectPrefix[0] != 0x05 || connectPrefix[1] != 0x01 || connectPrefix[3] != 0x03)
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            uint8_t hostLength = connectPrefix[4];
            std::string connectSuffix(hostLength + 2, 0);
            if (!recvAllFromFd(fds[1], &connectSuffix[0], connectSuffix.size(), 1000))
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            const uint8_t connectResponse[4] = {0x05, 0x00, 0x01, 0x01};
            if (!sendAllToFd(fds[1], connectResponse, sizeof(connectResponse), 1000))
            {
                serverScriptOk = false;
            }

            Socket::closeSocket(fds[1]);
        });

        ProxyConfig proxy;
        proxy.type = ProxyType::Socks5;

        std::string errMsg;
        bool success = ProxyConnect::connect(
            fds[0], proxy, "example.org", 443, errMsg, makeTimeoutCancellation(3000));

        Socket::closeSocket(fds[0]);
        scriptedProxy.join();

        REQUIRE(serverScriptOk.load());
        REQUIRE_FALSE(success);
        REQUIRE(errMsg == "Invalid SOCKS5 reserved byte in connect response");
#endif
    }

    SECTION("SOCKS5 rejects unsupported address type in connect response")
    {
#ifdef _WIN32
        SUCCEED("socketpair-based SOCKS5 test is skipped on Windows");
#else
        int fds[2] = {-1, -1};
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        SocketConnect::configureSocket(fds[0]);
        SocketConnect::configureSocket(fds[1]);

        std::atomic<bool> serverScriptOk(true);
        std::thread scriptedProxy([&]() {
            uint8_t greeting[3]{};
            if (!recvAllFromFd(fds[1], greeting, sizeof(greeting), 1000) || greeting[0] != 0x05)
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            const uint8_t methodSelection[2] = {0x05, 0x00};
            if (!sendAllToFd(fds[1], methodSelection, sizeof(methodSelection), 1000))
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            uint8_t connectPrefix[5]{};
            if (!recvAllFromFd(fds[1], connectPrefix, sizeof(connectPrefix), 1000) ||
                connectPrefix[0] != 0x05 || connectPrefix[1] != 0x01 || connectPrefix[3] != 0x03)
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            uint8_t hostLength = connectPrefix[4];
            std::string connectSuffix(hostLength + 2, 0);
            if (!recvAllFromFd(fds[1], &connectSuffix[0], connectSuffix.size(), 1000))
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            const uint8_t connectResponse[4] = {0x05, 0x00, 0x00, 0x05}; // invalid ATYP
            if (!sendAllToFd(fds[1], connectResponse, sizeof(connectResponse), 1000))
            {
                serverScriptOk = false;
            }

            Socket::closeSocket(fds[1]);
        });

        ProxyConfig proxy;
        proxy.type = ProxyType::Socks5;

        std::string errMsg;
        bool success = ProxyConnect::connect(
            fds[0], proxy, "example.org", 443, errMsg, makeTimeoutCancellation(3000));

        Socket::closeSocket(fds[0]);
        scriptedProxy.join();

        REQUIRE(serverScriptOk.load());
        REQUIRE_FALSE(success);
        REQUIRE(errMsg == "SOCKS5 connect response has unsupported address type");
#endif
    }

    SECTION("SOCKS5 reports truncated bound address in connect response")
    {
#ifdef _WIN32
        SUCCEED("socketpair-based SOCKS5 test is skipped on Windows");
#else
        int fds[2] = {-1, -1};
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        SocketConnect::configureSocket(fds[0]);
        SocketConnect::configureSocket(fds[1]);

        std::atomic<bool> serverScriptOk(true);
        std::thread scriptedProxy([&]() {
            uint8_t greeting[3]{};
            if (!recvAllFromFd(fds[1], greeting, sizeof(greeting), 1000) || greeting[0] != 0x05)
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            const uint8_t methodSelection[2] = {0x05, 0x00};
            if (!sendAllToFd(fds[1], methodSelection, sizeof(methodSelection), 1000))
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            uint8_t connectPrefix[5]{};
            if (!recvAllFromFd(fds[1], connectPrefix, sizeof(connectPrefix), 1000) ||
                connectPrefix[0] != 0x05 || connectPrefix[1] != 0x01 || connectPrefix[3] != 0x03)
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            uint8_t hostLength = connectPrefix[4];
            std::string connectSuffix(hostLength + 2, 0);
            if (!recvAllFromFd(fds[1], &connectSuffix[0], connectSuffix.size(), 1000))
            {
                serverScriptOk = false;
                Socket::closeSocket(fds[1]);
                return;
            }

            const uint8_t connectResponse[4] = {0x05, 0x00, 0x00, 0x01};
            if (!sendAllToFd(fds[1], connectResponse, sizeof(connectResponse), 1000))
            {
                serverScriptOk = false;
            }

            Socket::closeSocket(fds[1]);
        });

        ProxyConfig proxy;
        proxy.type = ProxyType::Socks5;

        std::string errMsg;
        bool success = ProxyConnect::connect(
            fds[0], proxy, "example.org", 443, errMsg, makeTimeoutCancellation(3000));

        Socket::closeSocket(fds[0]);
        scriptedProxy.join();

        REQUIRE(serverScriptOk.load());
        REQUIRE_FALSE(success);
        REQUIRE(errMsg == "Failed to read SOCKS5 IPv4 bound address");
#endif
    }
}

#if defined(IXWEBSOCKET_USE_TLS)
TEST_CASE("https_proxy_tunnel", "[proxy][http]")
{
    int targetPort = getFreePort();
    HttpServer targetServer(targetPort, "127.0.0.1");
    targetServer.setOnConnectionCallback(
        [](HttpRequestPtr request, std::shared_ptr<ConnectionState>) -> HttpResponsePtr {
            if (request->uri == "/proxy-check")
            {
                return std::make_shared<HttpResponse>(
                    200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), "proxied");
            }

            return std::make_shared<HttpResponse>(404, "NOT FOUND");
        });

    auto targetListenError = targetServer.listen();
    REQUIRE(!targetListenError);
    targetServer.start();

    int proxyPort = getFreePort();
    ConnectProxyServer proxyServer(proxyPort, true, true);
    auto proxyListenError = proxyServer.listen();
    REQUIRE(!proxyListenError);
    proxyServer.start();

    std::string targetUrl = "http://127.0.0.1:" + std::to_string(targetPort) + "/proxy-check";

    SECTION("request fails without proxy credentials")
    {
        HttpClient httpClient;
        httpClient.setKeepAlive(false);

        ProxyConfig proxyConfig;
        proxyConfig.type = ProxyType::Https;
        proxyConfig.host = "127.0.0.1";
        proxyConfig.port = proxyPort;
        proxyConfig.tlsOptions.caFile = "NONE";
        proxyConfig.tlsOptions.disable_hostname_validation = true;
        proxyConfig.tlsOptions.ciphers = "ALL:@SECLEVEL=0";
        httpClient.setProxyConfig(proxyConfig);

        auto args = httpClient.createRequest(targetUrl);
        args->connectTimeout = 5;
        args->transferTimeout = 5;
        args->compress = false;

        auto response = httpClient.get(targetUrl, args);
        REQUIRE(response->errorCode == HttpErrorCode::CannotConnect);
        REQUIRE(response->statusCode == 0);
        REQUIRE(response->errorMsg.find("407") != std::string::npos);
    }

    SECTION("request succeeds through authenticated HTTPS proxy")
    {
        HttpClient httpClient;
        httpClient.setKeepAlive(false);

        ProxyConfig proxyConfig;
        proxyConfig.type = ProxyType::Https;
        proxyConfig.host = "127.0.0.1";
        proxyConfig.port = proxyPort;
        proxyConfig.username = "alice";
        proxyConfig.password = "secret";
        proxyConfig.tlsOptions.caFile = "NONE";
        proxyConfig.tlsOptions.disable_hostname_validation = true;
        proxyConfig.tlsOptions.ciphers = "ALL:@SECLEVEL=0";
        httpClient.setProxyConfig(proxyConfig);

        auto args = httpClient.createRequest(targetUrl);
        args->connectTimeout = 5;
        args->transferTimeout = 5;
        args->compress = false;

        auto response = httpClient.get(targetUrl, args);

        REQUIRE(response->statusCode == 200);
        REQUIRE((response->errorCode == HttpErrorCode::Ok ||
                 response->errorCode == HttpErrorCode::CannotReadBody));

        REQUIRE(proxyServer.getConnectCount() >= 1);
        REQUIRE(proxyServer.getEstablishedTunnelCount() >= 1);
        REQUIRE(proxyServer.getLastAuthorizationHeader().find("Basic ") == 0);
    }

    proxyServer.stop();
    targetServer.stop();
}

TEST_CASE("https_proxy_tunnel_strict_validation", "[proxy][http][https]")
{
    const std::string strictCertFile = ".certs/trusted-localhost-server-crt.pem";
    const std::string strictKeyFile = ".certs/trusted-localhost-server-key.pem";

    int targetPort = getFreePort();
    HttpServer targetServer(targetPort, "127.0.0.1");

    SocketTLSOptions targetTlsOptions;
    targetTlsOptions.tls = true;
    targetTlsOptions.caFile = "NONE";
    targetTlsOptions.certFile = strictCertFile;
    targetTlsOptions.keyFile = strictKeyFile;
    targetTlsOptions.ciphers = "ALL:@SECLEVEL=0";
    targetServer.setTLSOptions(targetTlsOptions);

    targetServer.setOnConnectionCallback(
        [](HttpRequestPtr request, std::shared_ptr<ConnectionState>) -> HttpResponsePtr {
            if (request->uri == "/proxy-check")
            {
                return std::make_shared<HttpResponse>(
                    200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), "strict-proxied");
            }

            return std::make_shared<HttpResponse>(404, "NOT FOUND");
        });

    auto targetListenError = targetServer.listen();
    INFO(targetListenError.value_or("target server listen ok"));
    REQUIRE(!targetListenError);
    targetServer.start();

    int proxyPort = getFreePort();
    ConnectProxyServer proxyServer(proxyPort, true, true, strictCertFile, strictKeyFile);
    auto proxyListenError = proxyServer.listen();
    INFO(proxyListenError.value_or("proxy server listen ok"));
    REQUIRE(!proxyListenError);
    proxyServer.start();

    std::string targetUrl = "https://localhost:" + std::to_string(targetPort) + "/proxy-check";

    auto makeProxyConfig = [proxyPort]() {
        ProxyConfig proxyConfig;
        proxyConfig.type = ProxyType::Https;
        proxyConfig.host = "localhost";
        proxyConfig.port = proxyPort;
        proxyConfig.username = "alice";
        proxyConfig.password = "secret";
        proxyConfig.tlsOptions.caFile = ".certs/trusted-ca-crt.pem";
        proxyConfig.tlsOptions.disable_hostname_validation = false;
        proxyConfig.tlsOptions.ciphers = "ALL:@SECLEVEL=0";
        return proxyConfig;
    };

    auto makeClientTlsOptions = []() {
        SocketTLSOptions tlsOptions;
        tlsOptions.caFile = ".certs/trusted-ca-crt.pem";
        tlsOptions.disable_hostname_validation = false;
        tlsOptions.ciphers = "ALL:@SECLEVEL=0";
        return tlsOptions;
    };

    SECTION("fails when proxy certificate is not trusted")
    {
        HttpClient httpClient;
        httpClient.setKeepAlive(false);
        httpClient.setTLSOptions(makeClientTlsOptions());

        auto proxyConfig = makeProxyConfig();
        proxyConfig.tlsOptions.caFile = ".certs/untrusted-ca-crt.pem";
        httpClient.setProxyConfig(proxyConfig);

        auto args = httpClient.createRequest(targetUrl);
        args->connectTimeout = 5;
        args->transferTimeout = 5;
        args->compress = false;

        auto response = httpClient.get(targetUrl, args);
        REQUIRE(response->errorCode == HttpErrorCode::CannotConnect);
        REQUIRE(response->statusCode == 0);
    }

    SECTION("fails when target certificate is not trusted")
    {
        HttpClient httpClient;
        httpClient.setKeepAlive(false);

        auto targetTls = makeClientTlsOptions();
        targetTls.caFile = ".certs/untrusted-ca-crt.pem";
        httpClient.setTLSOptions(targetTls);
        httpClient.setProxyConfig(makeProxyConfig());

        auto args = httpClient.createRequest(targetUrl);
        args->connectTimeout = 5;
        args->transferTimeout = 5;
        args->compress = false;

        auto response = httpClient.get(targetUrl, args);
        REQUIRE(response->errorCode == HttpErrorCode::CannotConnect);
        REQUIRE(response->statusCode == 0);
        REQUIRE(proxyServer.getEstablishedTunnelCount() >= 1);
    }

    SECTION("succeeds with strict validation on both proxy and target")
    {
        HttpClient httpClient;
        httpClient.setKeepAlive(false);
        httpClient.setTLSOptions(makeClientTlsOptions());
        httpClient.setProxyConfig(makeProxyConfig());

        auto args = httpClient.createRequest(targetUrl);
        args->connectTimeout = 5;
        args->transferTimeout = 5;
        args->compress = false;

        auto response = httpClient.get(targetUrl, args);
        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->body == "strict-proxied");

        REQUIRE(proxyServer.getConnectCount() >= 1);
        REQUIRE(proxyServer.getEstablishedTunnelCount() >= 1);
        REQUIRE(proxyServer.getLastAuthorizationHeader().find("Basic ") == 0);
    }

    proxyServer.stop();
    targetServer.stop();
}
#endif
