/*
 *  IXUdpSocket.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2020 Machine Zone, Inc. All rights reserved.
 */

#pragma once

#include <atomic>
#include <memory>
#include <string>

#include "IXIoResult.h"
#include "IXNetSystem.h"

namespace ix
{
    class UdpSocket
    {
    public:
        UdpSocket(int fd = -1);
        ~UdpSocket();

        // Virtual methods
        bool init(const std::string& host, int port, std::string& errMsg);
        IoResult sendto(const std::string& buffer);
        IoResult recvfrom(char* buffer, size_t length);

        void close();

        static int getErrno();
        static bool isWaitNeeded();
        static void closeSocket(int fd);

    private:
        std::atomic<int> _sockfd;
        struct sockaddr_storage _server;
        socklen_t _serverLen;
        int _addressFamily;
    };
} // namespace ix
