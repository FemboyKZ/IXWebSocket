/*
 *  IXSecureRandom.cpp
 *  Author: ProjectSky
 *  Copyright (c) 2026 SkyServers. All rights reserved.
 */

#include "IXSecureRandom.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <limits>

#ifdef _WIN32
#include <bcrypt.h>
#else
#include <unistd.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>
#elif defined(__linux__)
#include <fcntl.h>
#include <sys/random.h>
#endif
#endif

namespace ix
{
    namespace
    {
#ifndef _WIN32
#if defined(__linux__)
        bool secureRandomBytesWithGetrandom(uint8_t* data, size_t size)
        {
            size_t offset = 0;
            while (offset < size)
            {
                ssize_t result = ::getrandom(data + offset, size - offset, 0);
                if (result < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    return false;
                }
                if (result == 0)
                {
                    return false;
                }

                offset += static_cast<size_t>(result);
            }

            return true;
        }

        bool secureRandomBytesWithUrandom(uint8_t* data, size_t size)
        {
            int fd = ::open("/dev/urandom", O_RDONLY);
            if (fd < 0)
            {
                return false;
            }

            size_t offset = 0;
            while (offset < size)
            {
                ssize_t result = ::read(fd, data + offset, size - offset);
                if (result < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    ::close(fd);
                    return false;
                }
                if (result == 0)
                {
                    ::close(fd);
                    return false;
                }

                offset += static_cast<size_t>(result);
            }

            ::close(fd);
            return true;
        }
#endif
#endif
    } // namespace

    bool secureRandomBytes(void* data, size_t size)
    {
        if (size == 0)
        {
            return true;
        }
        if (data == nullptr)
        {
            return false;
        }

        auto* bytes = static_cast<uint8_t*>(data);

#ifdef _WIN32
        while (size > 0)
        {
            ULONG chunk = static_cast<ULONG>(
                std::min<size_t>(size, static_cast<size_t>(std::numeric_limits<ULONG>::max())));
            if (BCryptGenRandom(nullptr, bytes, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            {
                return false;
            }

            bytes += chunk;
            size -= chunk;
        }

        return true;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        arc4random_buf(bytes, size);
        return true;
#elif defined(__linux__)
        return secureRandomBytesWithGetrandom(bytes, size) ||
               secureRandomBytesWithUrandom(bytes, size);
#else
        static_cast<void>(bytes);
        static_cast<void>(size);
        return false;
#endif
    }
} // namespace ix
