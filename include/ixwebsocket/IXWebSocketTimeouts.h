/*
 *  IXWebSocketTimeouts.h
 *  Author: ProjectSky
 *  Copyright (c) 2025 SkyServers. All rights reserved.
 */

#pragma once

#include <algorithm>

namespace ix
{
    struct WebSocketTimeouts
    {
        int pingIntervalSecs = -1;      // -1 means disabled
        int pingTimeoutSecs = -1;       // -1 means disabled
        int idleTimeoutSecs = -1;       // -1 means disabled
        int sendTimeoutSecs = 300;
        int closeTimeoutSecs = 5;

        WebSocketTimeouts() = default;

        WebSocketTimeouts& setPingInterval(int secs)
        {
            pingIntervalSecs = normalizeOptionalTimeout(secs);
            return *this;
        }

        WebSocketTimeouts& setPingTimeout(int secs)
        {
            pingTimeoutSecs = normalizeOptionalTimeout(secs);
            return *this;
        }

        WebSocketTimeouts& setIdleTimeout(int secs)
        {
            idleTimeoutSecs = normalizeOptionalTimeout(secs);
            return *this;
        }

        WebSocketTimeouts& setSendTimeout(int secs)
        {
            sendTimeoutSecs = normalizeRequiredTimeout(secs);
            return *this;
        }

        WebSocketTimeouts& setCloseTimeout(int secs)
        {
            closeTimeoutSecs = normalizeRequiredTimeout(secs);
            return *this;
        }

    private:
        static int normalizeOptionalTimeout(int secs)
        {
            return std::max(secs, -1);
        }

        static int normalizeRequiredTimeout(int secs)
        {
            return std::max(secs, 1);
        }
    };
} // namespace ix
