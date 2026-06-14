/*
 *  IXSecureRandom.cpp
 *  Author: ProjectSky
 *  Copyright (c) 2026 SkyServers. All rights reserved.
 */

#pragma once

#include <cstddef>

namespace ix
{
    bool secureRandomBytes(void* data, size_t size);
} // namespace ix
