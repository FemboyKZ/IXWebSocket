/*
 *  IXBase64Test.cpp
 */

#include "catch.hpp"
#include <ixwebsocket/IXBase64.h>

TEST_CASE("base64", "[base64]")
{
    SECTION("encode handles empty and short inputs")
    {
        REQUIRE(macaron::Base64::Encode("") == "");
        REQUIRE(macaron::Base64::Encode("f") == "Zg==");
        REQUIRE(macaron::Base64::Encode("fo") == "Zm8=");
        REQUIRE(macaron::Base64::Encode("foo") == "Zm9v");
    }

    SECTION("decode handles empty input")
    {
        std::string out("unchanged");
        REQUIRE(macaron::Base64::Decode("", out).empty());
        REQUIRE(out.empty());
    }

    SECTION("decode rejects malformed input")
    {
        std::string out;
        REQUIRE(!macaron::Base64::Decode("A===", out).empty());
        REQUIRE(!macaron::Base64::Decode("AAAA====", out).empty());

        std::string nonAscii;
        nonAscii.push_back(static_cast<char>(0xff));
        nonAscii += "AAA";
        REQUIRE(!macaron::Base64::Decode(nonAscii, out).empty());
    }

    SECTION("decode handles valid padding")
    {
        std::string out;
        REQUIRE(macaron::Base64::Decode("Zg==", out).empty());
        REQUIRE(out == "f");

        REQUIRE(macaron::Base64::Decode("Zm8=", out).empty());
        REQUIRE(out == "fo");

        REQUIRE(macaron::Base64::Decode("Zm9v", out).empty());
        REQUIRE(out == "foo");
    }
}
