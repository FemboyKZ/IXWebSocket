/*
 *  IXUdpSocket.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2020 Machine Zone, Inc. All rights reserved.
 */

#include "IXUdpSocket.h"

#include "IXNetSystem.h"
#include <cstring>
#include <limits>
#include <sstream>

namespace ix
{
    UdpSocket::UdpSocket(int fd)
        : _sockfd(fd)
        , _server{}
        , _serverLen(0)
        , _addressFamily(AF_INET)
    {
    }

    UdpSocket::~UdpSocket()
    {
        close();
    }

    void UdpSocket::close()
    {
        int fd = _sockfd.exchange(-1);
        if (fd == -1) return;

        closeSocket(fd);
    }

    int UdpSocket::getErrno()
    {
        int err;

#ifdef _WIN32
        err = WSAGetLastError();
#else
        err = errno;
#endif

        return err;
    }

    bool UdpSocket::isWaitNeeded()
    {
        int err = getErrno();

        if (err == EWOULDBLOCK || err == EAGAIN || err == EINPROGRESS)
        {
            return true;
        }

        return false;
    }

    void UdpSocket::closeSocket(int fd)
    {
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
    }

    bool UdpSocket::init(const std::string& host, int port, std::string& errMsg)
    {
        close();

        if (port <= 0 || port > 65535)
        {
            errMsg = "Invalid UDP target port";
            return false;
        }

        // DNS resolution with IPv4/IPv6 support
        struct addrinfo hints{}, *result = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        std::string portStr = std::to_string(port);
        int ret = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result);
        if (ret != 0 || result == nullptr)
        {
            errMsg = gai_strerror(ret);
            if (result) freeaddrinfo(result);
            return false;
        }

        if (result->ai_addrlen > sizeof(_server))
        {
            errMsg = "Resolved UDP address is too large";
            freeaddrinfo(result);
            return false;
        }

        _addressFamily = result->ai_family;
        _sockfd = socket(_addressFamily, SOCK_DGRAM, IPPROTO_UDP);
        if (_sockfd < 0)
        {
            errMsg = "Could not create socket";
            freeaddrinfo(result);
            return false;
        }

#ifdef _WIN32
        unsigned long nonblocking = 1;
        if (ioctlsocket(_sockfd, FIONBIO, &nonblocking) != 0)
        {
            errMsg = "Could not set UDP socket to non-blocking mode";
            close();
            freeaddrinfo(result);
            return false;
        }
#else
        if (fcntl(_sockfd, F_SETFL, O_NONBLOCK) == -1)
        {
            errMsg = "Could not set UDP socket to non-blocking mode";
            close();
            freeaddrinfo(result);
            return false;
        }
#endif

        _server = {};
        memcpy(&_server, result->ai_addr, result->ai_addrlen);
        _serverLen = static_cast<socklen_t>(result->ai_addrlen);
        freeaddrinfo(result);

        return true;
    }

    IoResult UdpSocket::sendto(const std::string& buffer)
    {
        int fd = _sockfd.load();
        if (fd == -1) return {0, IoError::ConnectionClosed};

#ifdef _WIN32
        if (buffer.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
        {
            return {0, IoError::Error};
        }
        int length = static_cast<int>(buffer.size());
#else
        size_t length = buffer.size();
#endif

        auto ret = ::sendto(
            fd, buffer.data(), length, 0, (struct sockaddr*) &_server, _serverLen);
        if (ret >= 0) return {static_cast<size_t>(ret), IoError::Success};
        if (isWaitNeeded()) return {0, IoError::WouldBlock};
        return {0, IoError::Error};
    }

    IoResult UdpSocket::recvfrom(char* buffer, size_t length)
    {
        int fd = _sockfd.load();
        if (fd == -1) return {0, IoError::ConnectionClosed};

#ifdef _WIN32
        if (length > static_cast<size_t>(std::numeric_limits<int>::max()))
        {
            return {0, IoError::Error};
        }
        int receiveLength = static_cast<int>(length);
        int addressLen = static_cast<int>(_serverLen);
#else
        size_t receiveLength = length;
        socklen_t addressLen = _serverLen;
#endif
        auto ret = ::recvfrom(
            fd, buffer, receiveLength, 0, (struct sockaddr*) &_server, &addressLen);
        if (ret >= 0) return {static_cast<size_t>(ret), IoError::Success};
        if (isWaitNeeded()) return {0, IoError::WouldBlock};
        return {0, IoError::Error};
    }
} // namespace ix
