/*
 *  IXWebSocketStats.h
 *  Author: ProjectSky
 *  Copyright (c) 2025 SkyServers. All rights reserved.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>

namespace ix
{
    struct WebSocketStats
    {
        WebSocketStats()
            : connectionStartTime(std::chrono::steady_clock::now())
        {
        }

        WebSocketStats(const WebSocketStats& other)
            : messagesSent(other.messagesSent.load())
            , messagesReceived(other.messagesReceived.load())
            , bytesSent(other.bytesSent.load())
            , bytesReceived(other.bytesReceived.load())
            , pingsSent(other.pingsSent.load())
            , pongsSent(other.pongsSent.load())
            , pingsReceived(other.pingsReceived.load())
            , pongsReceived(other.pongsReceived.load())
            , connectionStartTime(other.getConnectionStartTime())
        {
        }

        WebSocketStats& operator=(const WebSocketStats& other)
        {
            if (this == &other)
            {
                return *this;
            }

            messagesSent = other.messagesSent.load();
            messagesReceived = other.messagesReceived.load();
            bytesSent = other.bytesSent.load();
            bytesReceived = other.bytesReceived.load();
            pingsSent = other.pingsSent.load();
            pongsSent = other.pongsSent.load();
            pingsReceived = other.pingsReceived.load();
            pongsReceived = other.pongsReceived.load();
            setConnectionStartTime(other.getConnectionStartTime());

            return *this;
        }

        std::atomic<uint64_t> messagesSent{0};
        std::atomic<uint64_t> messagesReceived{0};
        std::atomic<uint64_t> bytesSent{0};
        std::atomic<uint64_t> bytesReceived{0};
        std::atomic<uint64_t> pingsSent{0};
        std::atomic<uint64_t> pongsSent{0};
        std::atomic<uint64_t> pingsReceived{0};
        std::atomic<uint64_t> pongsReceived{0};
        std::chrono::time_point<std::chrono::steady_clock> connectionStartTime;
        mutable std::mutex connectionStartTimeMutex;

        void reset()
        {
            messagesSent = 0;
            messagesReceived = 0;
            bytesSent = 0;
            bytesReceived = 0;
            pingsSent = 0;
            pongsSent = 0;
            pingsReceived = 0;
            pongsReceived = 0;
            setConnectionStartTime(std::chrono::steady_clock::now());
        }

        int64_t connectionDurationSecs() const
        {
            auto now = std::chrono::steady_clock::now();
            auto start = getConnectionStartTime();
            return std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
        }

    private:
        std::chrono::time_point<std::chrono::steady_clock> getConnectionStartTime() const
        {
            std::lock_guard<std::mutex> lock(connectionStartTimeMutex);
            return connectionStartTime;
        }

        void setConnectionStartTime(
            std::chrono::time_point<std::chrono::steady_clock> connectionStartTimeIn)
        {
            std::lock_guard<std::mutex> lock(connectionStartTimeMutex);
            connectionStartTime = connectionStartTimeIn;
        }
    };
} // namespace ix
