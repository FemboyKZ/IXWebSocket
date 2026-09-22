/*
 *  IXHttpConnectionPool.cpp
 *  Author: ProjectSky
 *  Copyright (c) 2025 SkyServers. All rights reserved.
 */

#include "IXHttpConnectionPool.h"
#include "IXSocketFactory.h"
#include <algorithm>

namespace ix
{
    HttpConnectionPool& HttpConnectionPool::getInstance()
    {
        static HttpConnectionPool instance;
        return instance;
    }

    std::string HttpConnectionPool::makeKey(const std::string& host, int port, bool tls) const
    {
        return host + ":" + std::to_string(port) + (tls ? ":tls" : "");
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

    std::unique_ptr<Socket> HttpConnectionPool::acquire(const std::string& host,
                                                        int port,
                                                        bool tls,
                                                        const SocketTLSOptions& tlsOptions,
                                                        std::string& errorMsg)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        cleanup();

        std::string key = makeKey(host, port, tls);
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
                                     bool tls)
    {
        if (!socket || !socket->isOpen()) return;

        std::lock_guard<std::mutex> lock(_mutex);
        std::string key = makeKey(host, port, tls);

        auto& connections = _pool[key];
        if (connections.size() >= _maxConnectionsPerHost)
        {
            return; // Drop connection, pool is full
        }

        connections.push_back({std::move(socket), std::chrono::steady_clock::now()});
    }

    void HttpConnectionPool::setMaxConnectionsPerHost(size_t max)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _maxConnectionsPerHost = max;
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
