/*
 *  IXWebSocketPerMessageDeflateCodecTest.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2020 Machine Zone. All rights reserved.
 *
 *  make build_test && build/test/ixwebsocket_unittest per-message-deflate-codec
 */

#include "IXTest.h"
#include "catch.hpp"
#include <iostream>
#include <ixwebsocket/IXWebSocketPerMessageDeflateCodec.h>
#include <ixwebsocket/IXWebSocketPerMessageDeflateOptions.h>
#include <string.h>

namespace ix
{
    std::string compressAndDecompress(const std::string& a)
    {
        std::string b, c;

        WebSocketPerMessageDeflateCompressor compressor;
        compressor.init(11, true);
        compressor.compress(a, b);

        WebSocketPerMessageDeflateDecompressor decompressor;
        decompressor.init(11, true);
        decompressor.decompress(b, c);

        return c;
    }

    std::string compressAndDecompressVector(const std::string& a)
    {
        std::string b, c;

        std::vector<uint8_t> vec(a.begin(), a.end());

        WebSocketPerMessageDeflateCompressor compressor;
        compressor.init(11, true);
        compressor.compress(vec, b);

        WebSocketPerMessageDeflateDecompressor decompressor;
        decompressor.init(11, true);
        decompressor.decompress(b, c);

        return c;
    }

    TEST_CASE("per-message-deflate-codec", "[zlib]")
    {
        SECTION("string api")
        {
            REQUIRE(compressAndDecompress("") == "");
            REQUIRE(compressAndDecompress("foo") == "foo");
            REQUIRE(compressAndDecompress("bar") == "bar");
            REQUIRE(compressAndDecompress("asdcaseqw`21897dehqwed") == "asdcaseqw`21897dehqwed");
            REQUIRE(compressAndDecompress("/usr/local/include/ixwebsocket/IXSocketOpenSSL.h") ==
                    "/usr/local/include/ixwebsocket/IXSocketOpenSSL.h");
        }

        SECTION("vector api")
        {
            REQUIRE(compressAndDecompressVector("") == "");
            REQUIRE(compressAndDecompressVector("foo") == "foo");
            REQUIRE(compressAndDecompressVector("bar") == "bar");
            REQUIRE(compressAndDecompressVector("asdcaseqw`21897dehqwed") ==
                    "asdcaseqw`21897dehqwed");
            REQUIRE(
                compressAndDecompressVector("/usr/local/include/ixwebsocket/IXSocketOpenSSL.h") ==
                "/usr/local/include/ixwebsocket/IXSocketOpenSSL.h");
        }

        SECTION("options parser clamps malformed window bits before narrowing")
        {
            WebSocketPerMessageDeflateOptions explicitOptions(true, false, false, 1, 255);
            REQUIRE(static_cast<int>(explicitOptions.getClientMaxWindowBits()) == 9);
            REQUIRE(static_cast<int>(explicitOptions.getServerMaxWindowBits()) == 15);

            WebSocketPerMessageDeflateOptions negative(
                "permessage-deflate; server_max_window_bits=-1; client_max_window_bits=-1");
            REQUIRE(negative.enabled());
            REQUIRE(static_cast<int>(negative.getServerMaxWindowBits()) == 8);
            REQUIRE(static_cast<int>(negative.getClientMaxWindowBits()) == 9);

            WebSocketPerMessageDeflateOptions oversized(
                "permessage-deflate; server_max_window_bits=999; client_max_window_bits=999");
            REQUIRE(static_cast<int>(oversized.getServerMaxWindowBits()) == 15);
            REQUIRE(static_cast<int>(oversized.getClientMaxWindowBits()) == 15);

            WebSocketPerMessageDeflateOptions malformed(
                "permessage-deflate; server_max_window_bits=12x; client_max_window_bits=12x");
            REQUIRE(static_cast<int>(malformed.getServerMaxWindowBits()) == 8);
            REQUIRE(static_cast<int>(malformed.getClientMaxWindowBits()) == 9);
        }
    }

} // namespace ix
