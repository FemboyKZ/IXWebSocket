/*
 *  IXProxyConnect.cpp
 *  Author: ProjectSky
 *  Copyright (c) 2025 SkyServers. All rights reserved.
 */

#include "IXProxyConnect.h"
#include "IXBase64.h"
#include "IXHttp.h"
#include "IXNetSystem.h"
#include "IXSocket.h"
#include <algorithm>
#include <charconv>
#include <cstring>
#include <limits>
#include <sstream>

namespace ix
{
    namespace
    {
        constexpr size_t kMaxProxyResponseLineLength = 8192;
        constexpr size_t kMaxProxyResponseHeaderCount = 100;
        constexpr size_t kMaxProxyResponseHeaderBytes = 64 * 1024;

        bool isValidPort(int port)
        {
            return port > 0 && port <= 65535;
        }

        bool parseProxyHttpStatusLine(const std::string& statusLine, int& statusCode)
        {
            if (statusLine.size() < 12 || statusLine.rfind("HTTP/1.", 0) != 0 ||
                (statusLine[7] != '0' && statusLine[7] != '1') || statusLine[8] != ' ')
            {
                return false;
            }

            const char* statusBegin = statusLine.data() + 9;
            const char* statusEnd = statusBegin + 3;
            auto result = std::from_chars(statusBegin, statusEnd, statusCode);
            if (result.ec != std::errc() || result.ptr != statusEnd)
            {
                return false;
            }

            return statusLine.size() == 12 || statusLine[12] == ' ' || statusLine[12] == '\r';
        }

        template<typename ReadLine>
        bool readAndDiscardProxyHeaders(ReadLine readLine,
                                        std::string& errMsg,
                                        const char* readErrorMsg)
        {
            size_t headerCount = 0;
            size_t headerBytes = 0;

            while (true)
            {
                std::string header;
                if (!readLine(header))
                {
                    errMsg = readErrorMsg;
                    return false;
                }

                if (header.size() > kMaxProxyResponseHeaderBytes - headerBytes)
                {
                    errMsg = "Proxy response headers are too large";
                    return false;
                }
                headerBytes += header.size();

                if (header == "\r\n") return true;

                if (++headerCount > kMaxProxyResponseHeaderCount)
                {
                    errMsg = "Proxy response has too many headers";
                    return false;
                }
            }
        }
    }

    bool ProxyConnect::rawSend(int sockfd, const std::string& data,
                               const CancellationRequest& isCancellationRequested)
    {
        size_t offset = 0;
        size_t len = data.size();

        while (offset < len)
        {
            if (isCancellationRequested && isCancellationRequested()) return false;

            int flags = 0;
#ifdef MSG_NOSIGNAL
            flags = MSG_NOSIGNAL;
#endif
            const size_t remaining = len - offset;
            const size_t ioLength =
                std::min(remaining, static_cast<size_t>(std::numeric_limits<int>::max()));
            auto ret = ::send(sockfd, data.c_str() + offset, ioLength, flags);

            if (ret > 0)
            {
                offset += ret;
            }
            else if (ret < 0 && Socket::isWaitNeeded())
            {
                struct pollfd pfd;
                pfd.fd = sockfd;
                pfd.events = POLLOUT;
                ix::poll(&pfd, 1, 100, nullptr);
                continue;
            }
            else
            {
                return false;
            }
        }
        return true;
    }

    bool ProxyConnect::rawRecv(int sockfd, void* buffer, size_t len,
                               const CancellationRequest& isCancellationRequested)
    {
        size_t offset = 0;
        char* buf = static_cast<char*>(buffer);

        while (offset < len)
        {
            if (isCancellationRequested && isCancellationRequested()) return false;

            int flags = 0;
#ifdef MSG_NOSIGNAL
            flags = MSG_NOSIGNAL;
#endif
            const size_t remaining = len - offset;
            const size_t ioLength =
                std::min(remaining, static_cast<size_t>(std::numeric_limits<int>::max()));
            auto ret = ::recv(sockfd, buf + offset, ioLength, flags);

            if (ret > 0)
            {
                offset += ret;
            }
            else if (ret < 0 && Socket::isWaitNeeded())
            {
                struct pollfd pfd;
                pfd.fd = sockfd;
                pfd.events = POLLIN;
                ix::poll(&pfd, 1, 100, nullptr);
                continue;
            }
            else
            {
                return false;
            }
        }
        return true;
    }

    bool ProxyConnect::rawSend(Socket& socket,
                               const std::string& data,
                               const CancellationRequest& isCancellationRequested)
    {
        size_t offset = 0;
        size_t len = data.size();

        while (offset < len)
        {
            if (isCancellationRequested && isCancellationRequested()) return false;

            auto result = socket.send(data.c_str() + offset, len - offset);
            if (result)
            {
                offset += result.bytes;
            }
            else if (result.wouldBlock())
            {
                if (socket.isReadyToWrite(100) == PollResultType::Error)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    bool ProxyConnect::rawRecv(Socket& socket,
                               void* buffer,
                               size_t len,
                               const CancellationRequest& isCancellationRequested)
    {
        size_t offset = 0;
        char* buf = static_cast<char*>(buffer);

        while (offset < len)
        {
            if (isCancellationRequested && isCancellationRequested()) return false;

            auto result = socket.recv(buf + offset, len - offset);
            if (result)
            {
                offset += result.bytes;
            }
            else if (result.wouldBlock())
            {
                if (socket.isReadyToRead(100) == PollResultType::Error)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    bool ProxyConnect::rawRecvLine(int sockfd, std::string& line,
                                   const CancellationRequest& isCancellationRequested)
    {
        line.clear();
        char c;
        while (true)
        {
            if (!rawRecv(sockfd, &c, 1, isCancellationRequested)) return false;

            if (line.size() >= kMaxProxyResponseLineLength)
            {
                return false;
            }

            line += c;
            if (line.size() >= 2 && line[line.size() - 2] == '\r' && line[line.size() - 1] == '\n')
            {
                return true;
            }
        }
    }

    bool ProxyConnect::rawRecvLine(Socket& socket,
                                   std::string& line,
                                   const CancellationRequest& isCancellationRequested)
    {
        line.clear();
        char c;
        while (true)
        {
            if (!rawRecv(socket, &c, 1, isCancellationRequested)) return false;

            if (line.size() >= kMaxProxyResponseLineLength)
            {
                return false;
            }

            line += c;
            if (line.size() >= 2 && line[line.size() - 2] == '\r' && line[line.size() - 1] == '\n')
            {
                return true;
            }
        }
    }

    bool ProxyConnect::connect(int sockfd,
                               const ProxyConfig& proxy,
                               const std::string& targetHost,
                               int targetPort,
                               std::string& errMsg,
                               const CancellationRequest& isCancellationRequested)
    {
        if (!isValidPort(targetPort))
        {
            errMsg = "Invalid proxy CONNECT target port";
            return false;
        }

        switch (proxy.type)
        {
            case ProxyType::Http:
                return httpConnect(sockfd, proxy, targetHost, targetPort, errMsg, isCancellationRequested);
            case ProxyType::Https:
                errMsg = "HTTPS proxy requires a TLS stream; use the socket-based CONNECT path.";
                return false;
            case ProxyType::Socks5:
                return socks5Connect(sockfd, proxy, targetHost, targetPort, errMsg, isCancellationRequested);
            default:
                errMsg = "Unknown proxy type";
                return false;
        }
    }

    bool ProxyConnect::connect(Socket& socket,
                               const ProxyConfig& proxy,
                               const std::string& targetHost,
                               int targetPort,
                               std::string& errMsg,
                               const CancellationRequest& isCancellationRequested)
    {
        if (!isValidPort(targetPort))
        {
            errMsg = "Invalid proxy CONNECT target port";
            return false;
        }

        switch (proxy.type)
        {
            case ProxyType::Http:
            case ProxyType::Https:
                return httpConnect(
                    socket, proxy, targetHost, targetPort, errMsg, isCancellationRequested);
            case ProxyType::Socks5:
                errMsg = "SOCKS5 is not supported on pre-established proxy streams";
                return false;
            default:
                errMsg = "Unknown proxy type";
                return false;
        }
    }

    bool ProxyConnect::httpConnect(int sockfd,
                                   const ProxyConfig& proxy,
                                   const std::string& targetHost,
                                   int targetPort,
                                   std::string& errMsg,
                                   const CancellationRequest& isCancellationRequested)
    {
        if (!isValidHttpAuthority(targetHost))
        {
            errMsg = "Invalid proxy CONNECT target host";
            return false;
        }

        const std::string targetAuthorityHost = formatHttpHost(targetHost);
        std::stringstream ss;
        ss << "CONNECT " << targetAuthorityHost << ":" << targetPort << " HTTP/1.1\r\n";
        ss << "Host: " << targetAuthorityHost << ":" << targetPort << "\r\n";

        if (proxy.requiresAuth())
        {
            ss << "Proxy-Authorization: " << buildBasicAuthHeader(proxy.username, proxy.password) << "\r\n";
        }

        ss << "\r\n";

        if (!rawSend(sockfd, ss.str(), isCancellationRequested))
        {
            errMsg = "Failed to send CONNECT request to proxy";
            return false;
        }

        std::string statusLine;
        if (!rawRecvLine(sockfd, statusLine, isCancellationRequested))
        {
            errMsg = "Failed to read proxy response";
            return false;
        }

        int statusCode = 0;
        if (!parseProxyHttpStatusLine(statusLine, statusCode))
        {
            errMsg = "Invalid proxy response: " + statusLine;
            return false;
        }

        if (!readAndDiscardProxyHeaders(
                [&](std::string& header) {
                    return rawRecvLine(sockfd, header, isCancellationRequested);
                },
                errMsg,
                "Failed to read proxy headers"))
        {
            return false;
        }

        if (statusCode == 200) return true;

        errMsg = "Proxy CONNECT failed with status: " + std::to_string(statusCode);
        return false;
    }

    bool ProxyConnect::httpConnect(Socket& socket,
                                   const ProxyConfig& proxy,
                                   const std::string& targetHost,
                                   int targetPort,
                                   std::string& errMsg,
                                   const CancellationRequest& isCancellationRequested)
    {
        if (!isValidHttpAuthority(targetHost))
        {
            errMsg = "Invalid proxy CONNECT target host";
            return false;
        }

        const std::string targetAuthorityHost = formatHttpHost(targetHost);
        std::stringstream ss;
        ss << "CONNECT " << targetAuthorityHost << ":" << targetPort << " HTTP/1.1\r\n";
        ss << "Host: " << targetAuthorityHost << ":" << targetPort << "\r\n";

        if (proxy.requiresAuth())
        {
            ss << "Proxy-Authorization: " << buildBasicAuthHeader(proxy.username, proxy.password)
               << "\r\n";
        }

        ss << "\r\n";

        if (!rawSend(socket, ss.str(), isCancellationRequested))
        {
            errMsg = "Failed to send CONNECT request to proxy";
            return false;
        }

        std::string statusLine;
        if (!rawRecvLine(socket, statusLine, isCancellationRequested))
        {
            errMsg = "Failed to read proxy response";
            return false;
        }

        int statusCode = 0;
        if (!parseProxyHttpStatusLine(statusLine, statusCode))
        {
            errMsg = "Invalid proxy response: " + statusLine;
            return false;
        }

        if (!readAndDiscardProxyHeaders(
                [&](std::string& header) {
                    return rawRecvLine(socket, header, isCancellationRequested);
                },
                errMsg,
                "Failed to read proxy headers"))
        {
            return false;
        }

        if (statusCode == 200) return true;

        errMsg = "Proxy CONNECT failed with status: " + std::to_string(statusCode);
        return false;
    }

    bool ProxyConnect::socks5Connect(int sockfd,
                                     const ProxyConfig& proxy,
                                     const std::string& targetHost,
                                     int targetPort,
                                     std::string& errMsg,
                                     const CancellationRequest& isCancellationRequested)
    {
        // Step 1: Send greeting with auth methods
        std::string greeting;
        greeting.push_back(0x05); // SOCKS5 version
        if (proxy.requiresAuth())
        {
            greeting.push_back(0x02); // 2 methods
            greeting.push_back(0x00); // No auth
            greeting.push_back(0x02); // Username/password
        }
        else
        {
            greeting.push_back(0x01); // 1 method
            greeting.push_back(0x00); // No auth
        }

        if (!rawSend(sockfd, greeting, isCancellationRequested))
        {
            errMsg = "Failed to send SOCKS5 greeting";
            return false;
        }

        // Step 2: Read server's chosen method
        uint8_t response[2];
        if (!rawRecv(sockfd, response, 2, isCancellationRequested))
        {
            errMsg = "Failed to read SOCKS5 greeting response";
            return false;
        }

        if (response[0] != 0x05)
        {
            errMsg = "Invalid SOCKS5 version in response";
            return false;
        }

        if (response[1] == 0xFF)
        {
            errMsg = "SOCKS5 server rejected all auth methods";
            return false;
        }

        if (response[1] != 0x00 && response[1] != 0x02)
        {
            errMsg = "SOCKS5 server selected unsupported auth method";
            return false;
        }

        // Step 3: Username/password auth if required
        if (response[1] == 0x02)
        {
            if (!proxy.requiresAuth())
            {
                errMsg = "SOCKS5 server requires auth but no credentials provided";
                return false;
            }

            if (proxy.username.size() > 255 || proxy.password.size() > 255)
            {
                errMsg = "SOCKS5 username or password exceeds 255 bytes";
                return false;
            }

            std::string authRequest;
            authRequest.push_back(0x01); // Auth version
            authRequest.push_back(static_cast<char>(proxy.username.size()));
            authRequest += proxy.username;
            authRequest.push_back(static_cast<char>(proxy.password.size()));
            authRequest += proxy.password;

            if (!rawSend(sockfd, authRequest, isCancellationRequested))
            {
                errMsg = "Failed to send SOCKS5 auth request";
                return false;
            }

            uint8_t authResponse[2];
            if (!rawRecv(sockfd, authResponse, 2, isCancellationRequested))
            {
                errMsg = "Failed to read SOCKS5 auth response";
                return false;
            }

            if (authResponse[0] != 0x01)
            {
                errMsg = "Invalid SOCKS5 auth version in response";
                return false;
            }

            if (authResponse[1] != 0x00)
            {
                errMsg = "SOCKS5 authentication failed";
                return false;
            }
        }

        // Step 4: Send connect request
        if (targetHost.size() > 255)
        {
            errMsg = "SOCKS5 target host exceeds 255 bytes";
            return false;
        }

        std::string connectRequest;
        connectRequest.push_back(0x05); // Version
        connectRequest.push_back(0x01); // Connect command
        connectRequest.push_back(0x00); // Reserved

        // Use domain name (ATYP = 0x03)
        connectRequest.push_back(0x03);
        connectRequest.push_back(static_cast<char>(targetHost.size()));
        connectRequest += targetHost;

        // Port in network byte order
        connectRequest.push_back(static_cast<char>((targetPort >> 8) & 0xFF));
        connectRequest.push_back(static_cast<char>(targetPort & 0xFF));

        if (!rawSend(sockfd, connectRequest, isCancellationRequested))
        {
            errMsg = "Failed to send SOCKS5 connect request";
            return false;
        }

        // Step 5: Read connect response
        uint8_t connectResponse[4];
        if (!rawRecv(sockfd, connectResponse, 4, isCancellationRequested))
        {
            errMsg = "Failed to read SOCKS5 connect response";
            return false;
        }

        if (connectResponse[0] != 0x05)
        {
            errMsg = "Invalid SOCKS5 version in connect response";
            return false;
        }

        if (connectResponse[1] != 0x00)
        {
            const char* errors[] = {
                "succeeded",
                "general SOCKS server failure",
                "connection not allowed by ruleset",
                "network unreachable",
                "host unreachable",
                "connection refused",
                "TTL expired",
                "command not supported",
                "address type not supported"
            };
            int errCode = connectResponse[1];
            errMsg = "SOCKS5 connect failed: ";
            errMsg += (errCode < 9) ? errors[errCode] : "unknown error";
            return false;
        }

        if (connectResponse[2] != 0x00)
        {
            errMsg = "Invalid SOCKS5 reserved byte in connect response";
            return false;
        }

        // Read and discard bound address
        uint8_t atyp = connectResponse[3];
        if (atyp == 0x01) // IPv4
        {
            uint8_t addr[4];
            if (!rawRecv(sockfd, addr, 4, isCancellationRequested))
            {
                errMsg = "Failed to read SOCKS5 IPv4 bound address";
                return false;
            }
        }
        else if (atyp == 0x03) // Domain
        {
            uint8_t len;
            if (!rawRecv(sockfd, &len, 1, isCancellationRequested))
            {
                errMsg = "Failed to read SOCKS5 domain bound address length";
                return false;
            }
            std::string domain(len, '\0');
            if (len > 0 && !rawRecv(sockfd, domain.data(), len, isCancellationRequested))
            {
                errMsg = "Failed to read SOCKS5 domain bound address";
                return false;
            }
        }
        else if (atyp == 0x04) // IPv6
        {
            uint8_t addr[16];
            if (!rawRecv(sockfd, addr, 16, isCancellationRequested))
            {
                errMsg = "Failed to read SOCKS5 IPv6 bound address";
                return false;
            }
        }
        else
        {
            errMsg = "SOCKS5 connect response has unsupported address type";
            return false;
        }

        // Read bound port
        uint8_t port[2];
        if (!rawRecv(sockfd, port, 2, isCancellationRequested))
        {
            errMsg = "Failed to read SOCKS5 bound port";
            return false;
        }

        return true;
    }

    std::string ProxyConnect::buildBasicAuthHeader(const std::string& username,
                                                   const std::string& password)
    {
        std::string credentials = username + ":" + password;
        return "Basic " + macaron::Base64::Encode(credentials);
    }
} // namespace ix
