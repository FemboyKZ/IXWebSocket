/*
 *  IXGzipCodec.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2020 Machine Zone, Inc. All rights reserved.
 */

#include "IXGzipCodec.h"

#include <algorithm>
#include <array>
#include <limits>
#include <string.h>
#include <utility>

#ifdef IXWEBSOCKET_USE_ZLIB
#include <zlib.h>
#endif

namespace
{
    constexpr size_t kMaxGzipDecompressedSize = 64ULL * 1024ULL * 1024ULL;
}

namespace ix
{
    bool gzipCompress(const std::string& str, std::string& out)
    {
        out.clear();
#ifndef IXWEBSOCKET_USE_ZLIB
        (void) str;
        return false;
#else
        z_stream zs{}; // z_stream is zlib's control structure

        // deflateInit2 configure the file format: request gzip instead of deflate
        const int windowBits = 15;
        const int GZIP_ENCODING = 16;

        if (deflateInit2(&zs,
                         Z_DEFAULT_COMPRESSION,
                         Z_DEFLATED,
                         windowBits | GZIP_ENCODING,
                         8,
                         Z_DEFAULT_STRATEGY) != Z_OK)
        {
            return false;
        }

        const auto* input = reinterpret_cast<const Bytef*>(str.data());
        size_t remaining = str.size();
        int ret = Z_OK;
        char outbuffer[32768];
        std::string outstring;

        // retrieve the compressed bytes blockwise
        while (ret != Z_STREAM_END)
        {
            if (zs.avail_in == 0 && remaining > 0)
            {
                const size_t inputSize =
                    std::min(remaining, static_cast<size_t>(std::numeric_limits<uInt>::max()));
                zs.next_in = const_cast<Bytef*>(input);
                zs.avail_in = static_cast<uInt>(inputSize);
                input += inputSize;
                remaining -= inputSize;
            }

            const int flush = remaining == 0 ? Z_FINISH : Z_NO_FLUSH;

            do
            {
                zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
                zs.avail_out = sizeof(outbuffer);

                ret = deflate(&zs, flush);
                if (ret != Z_OK && ret != Z_STREAM_END)
                {
                    deflateEnd(&zs);
                    out.clear();
                    return false;
                }

                const size_t outputSize = sizeof(outbuffer) - zs.avail_out;
                if (outputSize > 0)
                {
                    outstring.append(outbuffer, outputSize);
                }
            } while (zs.avail_out == 0);

            if (flush == Z_FINISH && zs.avail_in == 0 && ret != Z_STREAM_END)
            {
                continue;
            }
        }

        deflateEnd(&zs);

        out = std::move(outstring);
        return true;
#endif // IXWEBSOCKET_USE_ZLIB
    }

    std::string gzipCompress(const std::string& str)
    {
        std::string out;
        gzipCompress(str, out);
        return out;
    }

#ifdef IXWEBSOCKET_USE_DEFLATE
    static uint32_t loadDecompressedGzipSize(const uint8_t* p)
    {
        return ((uint32_t) p[0] << 0) | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) |
               ((uint32_t) p[3] << 24);
    }
#endif

    bool gzipDecompress(const std::string& in, std::string& out)
    {
        return gzipDecompress(in, out, kMaxGzipDecompressedSize);
    }

    bool gzipDecompress(const std::string& in, std::string& out, size_t maxOutputSize)
    {
#ifndef IXWEBSOCKET_USE_ZLIB
        (void) in;
        (void) out;
        (void) maxOutputSize;
        return false;
#else
        z_stream inflateState{};

        if (inflateInit2(&inflateState, 16 + MAX_WBITS) != Z_OK)
        {
            return false;
        }

        const auto* input = reinterpret_cast<const unsigned char*>(in.data());
        size_t remaining = in.size();
        out.clear();

        const int kBufferSize = 1 << 14;
        std::array<unsigned char, kBufferSize> compressBuffer;

        int ret = Z_OK;
        while (ret != Z_STREAM_END)
        {
            if (inflateState.avail_in == 0 && remaining > 0)
            {
                const size_t inputSize =
                    std::min(remaining, static_cast<size_t>(std::numeric_limits<uInt>::max()));
                inflateState.next_in = const_cast<unsigned char*>(input);
                inflateState.avail_in = static_cast<uInt>(inputSize);
                input += inputSize;
                remaining -= inputSize;
            }

            do
            {
                inflateState.avail_out = static_cast<uInt>(kBufferSize);
                inflateState.next_out = &compressBuffer.front();

                ret = inflate(&inflateState, Z_SYNC_FLUSH);

                if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR ||
                    ret == Z_BUF_ERROR)
                {
                    inflateEnd(&inflateState);
                    return false;
                }

                const size_t outputSize = kBufferSize - inflateState.avail_out;
                if (outputSize > maxOutputSize - out.size())
                {
                    inflateEnd(&inflateState);
                    out.clear();
                    return false;
                }

                out.append(reinterpret_cast<char*>(&compressBuffer.front()), outputSize);
            } while (inflateState.avail_out == 0);
        }

        inflateEnd(&inflateState);
        return true;
#endif // IXWEBSOCKET_USE_ZLIB
    }
} // namespace ix
