/*
 *  IXHttpConnectionPool.cpp
 *  Author: ProjectSky
 *  Copyright (c) 2025 SkyServers. All rights reserved.
 */

#include "IXHttpConnectionPool.h"
#include "IXSocketFactory.h"
#include <cstddef>

namespace ix
{
    namespace
    {
        void appendKeyPart(std::string& key, const std::string& value)
        {
            key += std::to_string(value.size());
            key += ':';
            key += value;
            key += ';';
        }

        void appendTLSOptions(std::string& key, const SocketTLSOptions& tlsOptions)
        {
            appendKeyPart(key, tlsOptions.certFile);
            appendKeyPart(key, tlsOptions.keyFile);
            appendKeyPart(key, tlsOptions.caFile);
            appendKeyPart(key, tlsOptions.ciphers);
            appendKeyPart(key, tlsOptions.tls ? "1" : "0");
            appendKeyPart(key, tlsOptions.disable_hostname_validation ? "1" : "0");
        }
    }

    HttpConnectionPool& HttpConnectionPool::getInstance()
    {
        static HttpConnectionPool instance;
        return instance;
    }

    std::string HttpConnectionPool::makeKey(const std::string& host,
                                            int port,
                                            bool tls,
                                            const SocketTLSOptions& tlsOptions,
                                            const ProxyConfig& proxyConfig) const
    {
        std::string key;
        appendKeyPart(key, host);
        appendKeyPart(key, std::to_string(port));
        appendKeyPart(key, tls ? "tls" : "plain");
        appendTLSOptions(key, tlsOptions);
        appendKeyPart(key, std::to_string(static_cast<int>(proxyConfig.type)));
        appendKeyPart(key, proxyConfig.host);
        appendKeyPart(key, std::to_string(proxyConfig.port));
        appendKeyPart(key, proxyConfig.username);
        appendKeyPart(key, proxyConfig.password);
        appendTLSOptions(key, proxyConfig.tlsOptions);
        return key;
    }

    void HttpConnectionPool::cleanup()
    {
        auto now = std::chrono::steady_clock::now();
        for (auto it = _pool.begin(); it != _pool.end();)
        {
            auto& connections = it->second;
            connections.erase(
                std::remove_if(connections.begin(), connections.end(),
                    [&](const PooledConnection& conn) {
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                            now - conn.lastUsed).count();
                        return elapsed > _idleTimeoutSecs || !conn.socket || !conn.socket->isOpen();
                    }),
                connections.end());

            if (connections.empty())
                it = _pool.erase(it);
            else
                ++it;
        }
    }

    size_t HttpConnectionPool::totalConnections() const
    {
        size_t count = 0;
        for (const auto& entry : _pool)
        {
            count += entry.second.size();
        }
        return count;
    }

    bool HttpConnectionPool::evictOldestConnection()
    {
        auto oldestEntry = _pool.end();
        auto oldestConnection = size_t{0};

        for (auto entry = _pool.begin(); entry != _pool.end(); ++entry)
        {
            auto& connections = entry->second;
            for (size_t i = 0; i < connections.size(); ++i)
            {
                if (oldestEntry == _pool.end() ||
                    connections[i].lastUsed < oldestEntry->second[oldestConnection].lastUsed)
                {
                    oldestEntry = entry;
                    oldestConnection = i;
                }
            }
        }

        if (oldestEntry == _pool.end())
        {
            return false;
        }

        auto& connections = oldestEntry->second;
        connections.erase(connections.begin() + static_cast<std::ptrdiff_t>(oldestConnection));
        if (connections.empty())
        {
            _pool.erase(oldestEntry);
        }
        return true;
    }

    std::unique_ptr<Socket> HttpConnectionPool::acquire(const std::string& host,
                                                        int port,
                                                        bool tls,
                                                        const SocketTLSOptions& tlsOptions,
                                                        const ProxyConfig& proxyConfig,
                                                        std::string& errorMsg)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        cleanup();

        std::string key = makeKey(host, port, tls, tlsOptions, proxyConfig);
        auto it = _pool.find(key);
        if (it != _pool.end())
        {
            // Try to find a valid socket from the pool
            while (!it->second.empty())
            {
                auto socket = std::move(it->second.back().socket);
                it->second.pop_back();
                if (socket && socket->isOpen())
                {
                    return socket;
                }
                // Socket was closed, try next one
            }
        }

        // Create new connection
        return createSocket(tls, -1, errorMsg, tlsOptions);
    }

    void HttpConnectionPool::release(std::unique_ptr<Socket> socket,
                                     const std::string& host,
                                     int port,
                                     bool tls,
                                     const SocketTLSOptions& tlsOptions,
                                     const ProxyConfig& proxyConfig)
    {
        if (!socket || !socket->isOpen()) return;

        std::lock_guard<std::mutex> lock(_mutex);
        cleanup();

        if (_maxTotalConnections == 0)
        {
            return;
        }

        std::string key = makeKey(host, port, tls, tlsOptions, proxyConfig);
        auto it = _pool.find(key);
        if (it != _pool.end() && it->second.size() >= _maxConnectionsPerHost)
        {
            return; // Drop connection, pool is full
        }

        while (totalConnections() >= _maxTotalConnections)
        {
            if (!evictOldestConnection())
            {
                return;
            }
        }

        auto& connections = _pool[key];
        connections.push_back({std::move(socket), std::chrono::steady_clock::now()});
    }

    void HttpConnectionPool::setMaxConnectionsPerHost(size_t max)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _maxConnectionsPerHost = max;
    }

    void HttpConnectionPool::setMaxTotalConnections(size_t max)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _maxTotalConnections = max;

        while (totalConnections() > _maxTotalConnections)
        {
            if (!evictOldestConnection())
            {
                break;
            }
        }
    }

    void HttpConnectionPool::setIdleTimeout(int seconds)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _idleTimeoutSecs = seconds;
    }

    void HttpConnectionPool::clear()
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _pool.clear();
    }
} // namespace ix
