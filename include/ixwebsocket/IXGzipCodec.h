/*
 *  IXGzipCodec.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2020 Machine Zone, Inc. All rights reserved.
 */

#pragma once

#include <cstddef>
#include <string>

namespace ix
{
    bool gzipCompress(const std::string& str, std::string& out);
    std::string gzipCompress(const std::string& str);
    bool gzipDecompress(const std::string& in, std::string& out);
    bool gzipDecompress(const std::string& in, std::string& out, size_t maxOutputSize);
} // namespace ix
