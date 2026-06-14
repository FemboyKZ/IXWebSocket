/*
 *  IXProxyConfig.cpp
 *  Author: ProjectSky
 *  Copyright (c) 2025 SkyServers. All rights reserved.
 */

#include "IXProxyConfig.h"
#include "IXUrlParser.h"

namespace ix
{
    ProxyConfig ProxyConfig::fromUrl(const std::string& url)
    {
        ProxyConfig config;
        fromUrl(url, config, nullptr);
        return config;
    }

    bool ProxyConfig::fromUrl(const std::string& url, ProxyConfig& config, std::string* errorMsg)
    {
        config = ProxyConfig();
        if (errorMsg)
        {
            errorMsg->clear();
        }

        if (url.empty())
        {
            return true;
        }

        std::string protocol, host, path, query;
        int port;

        if (!UrlParser::parse(url, protocol, host, path, query, port,
                              config.username, config.password))
        {
            if (errorMsg)
            {
                *errorMsg = "Invalid proxy URL";
            }
            return false;
        }

        if (protocol == "http")
        {
            config.type = ProxyType::Http;
        }
        else if (protocol == "https")
        {
            config.type = ProxyType::Https;
        }
        else if (protocol == "socks5")
        {
            config.type = ProxyType::Socks5;
        }
        else
        {
            if (errorMsg)
            {
                *errorMsg = "Unsupported proxy URL scheme";
            }
            config = ProxyConfig();
            return false;
        }

        config.host = host;
        config.port = (port > 0) ? port : (protocol == "socks5" ? 1080 : (protocol == "https" ? 443 : 80));

        return true;
    }
} // namespace ix
