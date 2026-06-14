/*
 *  IXIoResult.h
 *  Author: ProjectSky
 *  Copyright (c) 2025 SkyServers. All rights reserved.
 */

#pragma once

#include <cstddef>

namespace ix
{
    enum class IoError
    {
        Success,
        ConnectionClosed,
        WouldBlock,
        Error
    };

    struct IoResult
    {
        std::size_t bytes = 0;
        IoError error = IoError::Success;

        explicit operator bool() const { return error == IoError::Success; }
        bool wouldBlock() const { return error == IoError::WouldBlock; }
        bool closed() const { return error == IoError::ConnectionClosed; }
    };
} // namespace ix
