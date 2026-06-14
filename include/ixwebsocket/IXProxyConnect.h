/*
 *  IXProxyConnect.h
 *  Author: ProjectSky
 *  Copyright (c) 2025 SkyServers. All rights reserved.
 */

#pragma once

#include "IXCancellationRequest.h"
#include "IXProxyConfig.h"
#include <string>

namespace ix
{
    class Socket;

    class ProxyConnect
    {
    public:
        // Connect through proxy using raw socket fd (for use before TLS handshake)
        static bool connect(int sockfd,
                            const ProxyConfig& proxy,
                            const std::string& targetHost,
                            int targetPort,
                            std::string& errMsg,
                            const CancellationRequest& isCancellationRequested);

        // Connect through proxy using a stream-oriented socket. The passed
        // socket can be a plain socket or an already-established TLS socket
        // (used for HTTPS proxies).
        static bool connect(Socket& socket,
                            const ProxyConfig& proxy,
                            const std::string& targetHost,
                            int targetPort,
                            std::string& errMsg,
                            const CancellationRequest& isCancellationRequested);

    private:
        static bool httpConnect(int sockfd,
                                const ProxyConfig& proxy,
                                const std::string& targetHost,
                                int targetPort,
                                std::string& errMsg,
                                const CancellationRequest& isCancellationRequested);

        static bool socks5Connect(int sockfd,
                                  const ProxyConfig& proxy,
                                  const std::string& targetHost,
                                  int targetPort,
                                  std::string& errMsg,
                                  const CancellationRequest& isCancellationRequested);

        static bool httpConnect(Socket& socket,
                                const ProxyConfig& proxy,
                                const std::string& targetHost,
                                int targetPort,
                                std::string& errMsg,
                                const CancellationRequest& isCancellationRequested);

        static bool rawSend(int sockfd, const std::string& data,
                            const CancellationRequest& isCancellationRequested);
        static bool rawRecv(int sockfd, void* buffer, size_t len,
                            const CancellationRequest& isCancellationRequested);
        static bool rawRecvLine(int sockfd, std::string& line,
                                const CancellationRequest& isCancellationRequested);

        static bool rawSend(Socket& socket,
                            const std::string& data,
                            const CancellationRequest& isCancellationRequested);
        static bool rawRecv(Socket& socket,
                            void* buffer,
                            size_t len,
                            const CancellationRequest& isCancellationRequested);
        static bool rawRecvLine(Socket& socket,
                                std::string& line,
                                const CancellationRequest& isCancellationRequested);

        static std::string buildBasicAuthHeader(const std::string& username,
                                                const std::string& password);
    };
} // namespace ix
