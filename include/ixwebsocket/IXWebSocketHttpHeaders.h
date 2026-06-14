/*
 *  IXWebSocketHttpHeaders.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2018 Machine Zone, Inc. All rights reserved.
 */

#pragma once

#include "IXCancellationRequest.h"
#include "IXStrCaseCompare.h"
#include <map>
#include <memory>
#include <optional>
#include <string>

namespace ix
{
    class Socket;

    using WebSocketHttpHeaders = std::map<std::string, std::string, CaseInsensitiveLess>;

    std::optional<WebSocketHttpHeaders> parseHttpHeaders(
        std::unique_ptr<Socket>& socket, const CancellationRequest& isCancellationRequested);
    std::optional<WebSocketHttpHeaders> parseHttpHeaders(
        std::unique_ptr<Socket>& socket,
        const CancellationRequest& isCancellationRequested,
        int timeoutSecs);
} // namespace ix
