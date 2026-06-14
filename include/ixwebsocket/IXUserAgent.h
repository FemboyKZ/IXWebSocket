/*
 *  IXUserAgent.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone, Inc. All rights reserved.
 */

#pragma once

#include <string>

namespace ix
{
    std::string userAgent();

    // Custom user agent/server header
    void setUserAgent(const std::string& userAgent);
    void setServerHeader(const std::string& server);
    const std::string& getCustomUserAgent();
    const std::string& getCustomServerHeader();
} // namespace ix
