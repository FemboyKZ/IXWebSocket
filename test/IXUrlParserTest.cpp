/*
 *  IXSocketTest.cpp
 *  Author: Korchynskyi Dmytro
 *  Copyright (c) 2019 Machine Zone. All rights reserved.
 */

#include "IXTest.h"
#include "catch.hpp"
#include <iostream>
#include <ixwebsocket/IXUrlParser.h>
#include <string.h>

namespace ix
{
    TEST_CASE("urlParser", "[urlParser]")
    {
        SECTION("http://google.com")
        {
            std::string url = "http://google.com";
            std::string protocol, host, path, query;
            int port;
            bool res;

            res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(res);
            REQUIRE(protocol == "http");
            REQUIRE(host == "google.com");
            REQUIRE(path == "/");
            REQUIRE(query == "");
            REQUIRE(port == 80); // default port for http
        }

        SECTION("https://google.com")
        {
            std::string url = "https://google.com";
            std::string protocol, host, path, query;
            int port;
            bool res;

            res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(res);
            REQUIRE(protocol == "https");
            REQUIRE(host == "google.com");
            REQUIRE(path == "/");
            REQUIRE(query == "");
            REQUIRE(port == 443); // default port for https
        }

        SECTION("ws://google.com")
        {
            std::string url = "ws://google.com";
            std::string protocol, host, path, query;
            int port;
            bool res;

            res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(res);
            REQUIRE(protocol == "ws");
            REQUIRE(host == "google.com");
            REQUIRE(path == "/");
            REQUIRE(query == "");
            REQUIRE(port == 80); // default port for ws
        }

        SECTION("wss://google.com/ws?arg=value")
        {
            std::string url = "wss://google.com/ws?arg=value&arg2=value2";
            std::string protocol, host, path, query;
            int port;
            bool res;

            res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(res);
            REQUIRE(protocol == "wss");
            REQUIRE(host == "google.com");
            REQUIRE(path == "/ws?arg=value&arg2=value2");
            REQUIRE(query == "arg=value&arg2=value2");
            REQUIRE(port == 443); // default port for wss
        }

        SECTION("wss://google.com/?arg=value")
        {
            std::string url = "wss://google.com/?arg=value&arg2=value2";
            std::string protocol, host, path, query;
            int port;
            bool res;

            res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(res);
            REQUIRE(protocol == "wss");
            REQUIRE(host == "google.com");
            REQUIRE(path == "/?arg=value&arg2=value2");
            REQUIRE(query == "arg=value&arg2=value2");
            REQUIRE(port == 443); // default port for wss
        }

        SECTION("wss://google.com?arg=value")
        {
            std::string url = "wss://google.com?arg=value&arg2=value2";
            std::string protocol, host, path, query;
            int port;
            bool res;

            res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(res);
            REQUIRE(protocol == "wss");
            REQUIRE(host == "google.com");
            REQUIRE(path == "/?arg=value&arg2=value2");
            REQUIRE(query == "arg=value&arg2=value2");
            REQUIRE(port == 443); // default port for wss
        }

        SECTION("raw control characters are rejected")
        {
            std::string url = "http://example.com/\r\nInjected: header";
            std::string protocol, host, path, query;
            int port;

            bool res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(!res);
        }

        SECTION("empty scheme is rejected")
        {
            std::string url = "://example.com/";
            std::string protocol, host, path, query;
            int port;

            bool res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(!res);
        }

        SECTION("scheme can contain digits after the first character")
        {
            std::string url = "socks5://proxy.example/";
            std::string protocol, host, path, query;
            int port;

            bool res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(res);
            REQUIRE(protocol == "socks5");
            REQUIRE(host == "proxy.example");
            REQUIRE(path == "/");
        }

        SECTION("invalid explicit ports are rejected")
        {
            const char* invalidUrls[] = {"http://example.com:abc/",
                                         "http://example.com:12abc/",
                                         "http://example.com:/",
                                         "http://example.com:0/",
                                         "http://example.com:70000/"};

            for (const char* url : invalidUrls)
            {
                std::string protocol, host, path, query;
                int port;

                bool res = UrlParser::parse(url, protocol, host, path, query, port);

                REQUIRE(!res);
            }
        }

        SECTION("IPv6 literal host is parsed without authority brackets")
        {
            std::string url = "http://[::1]:8080/path";
            std::string protocol, host, path, query;
            int port;

            bool res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(res);
            REQUIRE(protocol == "http");
            REQUIRE(host == "::1");
            REQUIRE(path == "/path");
            REQUIRE(query == "");
            REQUIRE(port == 8080);
        }

        SECTION("IPv6 literal with missing closing bracket is rejected")
        {
            std::string url = "http://[::1/path";
            std::string protocol, host, path, query;
            int port;

            bool res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(!res);
        }

        SECTION("fragment after authority does not become part of host")
        {
            std::string url = "http://example.com#section";
            std::string protocol, host, path, query;
            int port;

            bool res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(res);
            REQUIRE(protocol == "http");
            REQUIRE(host == "example.com");
            REQUIRE(path == "/");
            REQUIRE(query == "");
            REQUIRE(port == 80);
        }

        SECTION("empty authority host is rejected")
        {
            const char* invalidUrls[] = {"http://", "http:///path", "http://?query", "http://#frag"};

            for (const char* url : invalidUrls)
            {
                std::string protocol, host, path, query;
                int port;

                bool res = UrlParser::parse(url, protocol, host, path, query, port);

                REQUIRE(!res);
            }
        }

        SECTION("real test")
        {
            std::string url =
                "ws://127.0.0.1:7350/"
                "ws?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJleHAiOjE1NTcxNzAwNzIsInVpZCI6ImMwZmZjOGE1LTk4OTktNDAwYi1hNGU5LTJjNWM3NjFmNWQxZi"
                "IsInVzbiI6InN2YmhOdlNJSmEifQ.5L8BUbpTA4XAHlSrdwhIVlrlIpRtjExepim7Yh5eEO4&status="
                "true&format=protobuf";
            std::string protocol, host, path, query;
            int port;
            bool res;

            res = UrlParser::parse(url, protocol, host, path, query, port);

            REQUIRE(res);
            REQUIRE(protocol == "ws");
            REQUIRE(host == "127.0.0.1");
            REQUIRE(path ==
                    "/ws?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                    "eyJleHAiOjE1NTcxNzAwNzIsInVpZCI6ImMwZmZjOGE1LTk4OTktNDAwYi1hNGU5LTJjNWM3NjFmNW"
                    "QxZiIsInVzbiI6InN2YmhOdlNJSmEifQ.5L8BUbpTA4XAHlSrdwhIVlrlIpRtjExepim7Yh5eEO4&"
                    "status=true&format=protobuf");
            REQUIRE(query ==
                    "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                    "eyJleHAiOjE1NTcxNzAwNzIsInVpZCI6ImMwZmZjOGE1LTk4OTktNDAwYi1hNGU5LTJjNWM3NjFmNW"
                    "QxZiIsInVzbiI6InN2YmhOdlNJSmEifQ.5L8BUbpTA4XAHlSrdwhIVlrlIpRtjExepim7Yh5eEO4&"
                    "status=true&format=protobuf");
            REQUIRE(port == 7350);
        }
    }

} // namespace ix
