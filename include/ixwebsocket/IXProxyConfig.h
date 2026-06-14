/*
 *  IXProxyConfig.h
 *  Author: ProjectSky
 *  Copyright (c) 2025 SkyServers. All rights reserved.
 */

#pragma once

#include "IXSocketTLSOptions.h"
#include <string>

namespace ix
{
    enum class ProxyType
    {
        None,
        Http,
        Https,
        Socks5
    };

    struct ProxyConfig
    {
        ProxyType type = ProxyType::None;
        std::string host;
        int port = 0;
        std::string username;
        std::string password;
        // TLS options for HTTPS proxies.
        SocketTLSOptions tlsOptions;

        bool hasValidPort() const { return port > 0 && port <= 65535; }
        bool isEnabled() const { return type != ProxyType::None && !host.empty() && hasValidPort(); }
        bool requiresAuth() const { return !username.empty(); }

        // Parse proxy URL: http://user:pass@host:port, socks5://host:port, etc.
        static ProxyConfig fromUrl(const std::string& url);
        static bool fromUrl(const std::string& url,
                            ProxyConfig& config,
                            std::string* errorMsg = nullptr);
    };
} // namespace ix
