/*
 *  IXTest.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2018 Machine Zone. All rights reserved.
 */

#pragma once

#include <iostream>
#include <ixwebsocket/IXGetFreePort.h>
#include <ixwebsocket/IXSocketTLSOptions.h>
#include <ixwebsocket/IXWebSocketServer.h>
#include <mutex>
#include <spdlog/spdlog.h>
#include <sstream>
#include <string>
#include <vector>

namespace ix
{
    // Sleep for ms milliseconds.
    void msleep(int ms);

    // Generate a relatively random string
    std::string generateSessionId();

    // Record and report websocket traffic
    void setupWebSocketTrafficTrackerCallback();
    void reportWebSocketTraffic();
    bool isTestLoggingEnabled();

    struct TLogger
    {
    public:
        TLogger() = default;
        TLogger(const TLogger&) = delete;
        TLogger& operator=(const TLogger&) = delete;

        ~TLogger()
        {
            auto message = _stream.str();
            if (message.empty()) return;

            if (!isTestLoggingEnabled())
            {
                bool isErrorMessage = message.find("error") != std::string::npos ||
                                      message.find("Error") != std::string::npos ||
                                      message.find("FAILED") != std::string::npos;
                if (!isErrorMessage) return;
            }

            std::lock_guard<std::mutex> lock(_mutex);
            if (message == _lastMessage) return;
            _lastMessage = message;
            spdlog::info(message);
        }

        template<typename T>
        TLogger& operator<<(T const& obj)
        {
            _stream << obj;
            return *this;
        }

    private:
        std::stringstream _stream;
        static std::mutex _mutex;
        static std::string _lastMessage;
    };

    void log(const std::string& msg);

    bool startWebSocketEchoServer(ix::WebSocketServer& server);

    SocketTLSOptions makeClientTLSOptions();
    SocketTLSOptions makeServerTLSOptions(bool preferTLS);
    std::string getHttpScheme();
    std::string getWsScheme(bool preferTLS);
} // namespace ix
