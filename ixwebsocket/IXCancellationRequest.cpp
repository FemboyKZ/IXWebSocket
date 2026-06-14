/*
 *  IXCancellationRequest.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone, Inc. All rights reserved.
 */

#include "IXCancellationRequest.h"

#include <chrono>

namespace ix
{
    CancellationRequest makeCancellationRequestWithTimeout(
        int secs, std::atomic<bool>& requestInitCancellation)
    {
        if (secs <= 0)
        {
            return [&requestInitCancellation]() -> bool { return requestInitCancellation.load(); };
        }

        auto start = std::chrono::steady_clock::now();
        auto timeout = std::chrono::seconds(secs);

        auto isCancellationRequested = [&requestInitCancellation, start, timeout]() -> bool {
            // Was an explicit cancellation requested ?
            if (requestInitCancellation) return true;

            auto now = std::chrono::steady_clock::now();
            if ((now - start) > timeout) return true;

            // No cancellation request
            return false;
        };

        return isCancellationRequested;
    }
} // namespace ix
