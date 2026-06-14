/*
 *  IXProgressCallback.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone, Inc. All rights reserved.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace ix
{
    using OnProgressCallback = std::function<bool(uint64_t current, uint64_t total)>;
    using OnChunkCallback = std::function<void(const std::string&)>;
}
