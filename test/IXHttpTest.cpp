/*
 *  IXHttpTest.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone. All rights reserved.
 */

#include "catch.hpp"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <ixwebsocket/IXGzipCodec.h>
#include <ixwebsocket/IXHttp.h>
#include <ixwebsocket/IXHttpClient.h>
#include <ixwebsocket/IXHttpConnectionPool.h>
#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXSocket.h>
#include <ixwebsocket/IXWebSocket.h>
#include <mutex>
#include <stdexcept>
#include <string.h>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/socket.h>
#endif

namespace ix
{
    namespace
    {
        class CaptureSocket final : public Socket
        {
        public:
            CaptureSocket()
                : Socket(-1)
            {
            }

            IoResult send(const char* buffer, size_t length) final
            {
                _written.append(buffer, length);
                return {length, IoError::Success};
            }

            const std::string& written() const
            {
                return _written;
            }

        private:
            std::string _written;
        };

        class ScriptedSocket final : public Socket
        {
        public:
            explicit ScriptedSocket(const std::string& input)
                : Socket(-1)
                , _input(input)
            {
            }

            IoResult recv(void* buffer, size_t length) final
            {
                if (_offset >= _input.size())
                {
                    return {0, IoError::ConnectionClosed};
                }

                const size_t bytesToCopy = std::min(length, _input.size() - _offset);
                memcpy(buffer, _input.data() + _offset, bytesToCopy);
                _offset += bytesToCopy;
                return {bytesToCopy, IoError::Success};
            }

        private:
            std::string _input;
            size_t _offset = 0;
        };

#ifndef _WIN32
        std::unique_ptr<Socket> makeOpenSocket(int& peerFd)
        {
            int fds[2] = {-1, -1};
            REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
            peerFd = fds[1];
            return std::unique_ptr<Socket>(new Socket(fds[0]));
        }
#endif
    }

    TEST_CASE("http", "[http]")
    {
        SECTION("Normal case")
        {
            std::string line = "HTTP/1.1 200";
            auto result = Http::parseStatusLine(line);

            REQUIRE(result.first == "HTTP/1.1");
            REQUIRE(result.second == 200);
        }

        SECTION("http/1.0 case")
        {
            std::string line = "HTTP/1.0 200";
            auto result = Http::parseStatusLine(line);

            REQUIRE(result.first == "HTTP/1.0");
            REQUIRE(result.second == 200);
        }

        SECTION("status line preserves reason phrase")
        {
            auto result = Http::parseStatusLineWithDescription("HTTP/1.1 404 Not Found\r\n");

            REQUIRE(std::get<0>(result) == "HTTP/1.1");
            REQUIRE(std::get<1>(result) == 404);
            REQUIRE(std::get<2>(result) == "Not Found");
        }

        SECTION("empty case")
        {
            std::string line = "";
            auto result = Http::parseStatusLine(line);

            REQUIRE(result.first == "");
            REQUIRE(result.second == -1);
        }

        SECTION("empty case")
        {
            std::string line = "HTTP/1.1";
            auto result = Http::parseStatusLine(line);

            REQUIRE(result.first == "HTTP/1.1");
            REQUIRE(result.second == -1);
        }

        SECTION("http header syntax validation")
        {
            REQUIRE(isValidHttpHeaderName("X-Test_Header"));
            REQUIRE(!isValidHttpHeaderName("Bad Header"));
            REQUIRE(!isValidHttpHeaderName("Bad:Header"));

            REQUIRE(isValidHttpHeaderValue("normal value\twith tab"));
            REQUIRE(!isValidHttpHeaderValue("bad\r\nInjected: value"));
            REQUIRE(!isValidHttpHeaderValue(std::string("bad\0value", 9)));
        }

        SECTION("http request target validation")
        {
            REQUIRE(isValidHttpRequestTarget("/path?query=value"));
            REQUIRE(!isValidHttpRequestTarget("/bad path"));
            REQUIRE(!isValidHttpRequestTarget("/bad\r\nInjected: value"));
        }

        SECTION("http authority validation")
        {
            REQUIRE(isValidHttpAuthority("example.com"));
            REQUIRE(isValidHttpAuthority("[::1]"));
            REQUIRE(!isValidHttpAuthority("example.com\r\nInjected: value"));
            REQUIRE(!isValidHttpAuthority("example.com/path"));
        }

        SECTION("http host formatting brackets IPv6 literals")
        {
            REQUIRE(formatHttpHost("example.com") == "example.com");
            REQUIRE(formatHttpHost("::1") == "[::1]");
            REQUIRE(formatHttpHost("[::1]") == "[::1]");
        }

        SECTION("sendResponse rejects conflicting framing headers")
        {
            auto socket = std::unique_ptr<Socket>(new CaptureSocket());
            auto response = std::make_shared<HttpResponse>(
                200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), "abc");
            response->headers["Transfer-Encoding"] = "chunked";
            response->headers["Content-Length"] = "3";

            REQUIRE(!Http::sendResponse(response, socket));
        }

        SECTION("sendResponse rejects null sockets")
        {
            std::unique_ptr<Socket> socket;
            auto response = std::make_shared<HttpResponse>(
                200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), "abc");

            REQUIRE(!Http::sendResponse(response, socket));
        }

        SECTION("sendResponse honors matching Content-Length")
        {
            auto* rawSocket = new CaptureSocket();
            auto socket = std::unique_ptr<Socket>(rawSocket);
            auto response = std::make_shared<HttpResponse>(
                200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), "abc");
            response->headers["Content-Length"] = "3";

            REQUIRE(Http::sendResponse(response, socket));

            const auto& written = rawSocket->written();
            REQUIRE(written.find("Content-Length: 3\r\n") != std::string::npos);
            REQUIRE(written.find("Content-Length: 3\r\nContent-Length: 3\r\n") ==
                    std::string::npos);
        }

        SECTION("sendResponse rejects mismatched Content-Length")
        {
            auto socket = std::unique_ptr<Socket>(new CaptureSocket());
            auto response = std::make_shared<HttpResponse>(
                200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), "abc");
            response->headers["Content-Length"] = "4";

            REQUIRE(!Http::sendResponse(response, socket));
        }

        SECTION("sendResponse terminates empty chunked responses")
        {
            auto* rawSocket = new CaptureSocket();
            auto socket = std::unique_ptr<Socket>(rawSocket);
            auto response = std::make_shared<HttpResponse>(
                200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), std::string());
            response->headers["Transfer-Encoding"] = "chunked";

            REQUIRE(Http::sendResponse(response, socket));
            REQUIRE(rawSocket->written().find("\r\n\r\n0\r\n\r\n") != std::string::npos);
        }

        SECTION("async HttpClient rejects invalid queued work")
        {
            HttpClient httpClient(true);
            auto args = httpClient.createRequest("http://example.com/");

            REQUIRE(!httpClient.performRequest(nullptr, [](const HttpResponsePtr&) {}));
            REQUIRE(!httpClient.performRequest(args, OnResponseCallback()));
        }

        SECTION("async HttpClient callback exceptions do not stop the worker")
        {
            HttpClient httpClient(true);
            auto firstRequest = httpClient.createRequest("ftp://example.com/");
            auto secondRequest = httpClient.createRequest("ftp://example.com/");

            std::mutex mutex;
            std::condition_variable condition;
            bool firstCallbackCalled = false;
            bool secondCallbackCalled = false;
            HttpErrorCode firstErrorCode = HttpErrorCode::Invalid;
            HttpErrorCode secondErrorCode = HttpErrorCode::Invalid;

            REQUIRE(httpClient.performRequest(
                firstRequest,
                [&](const HttpResponsePtr& response)
                {
                    firstErrorCode = response ? response->errorCode : HttpErrorCode::Invalid;
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        firstCallbackCalled = true;
                    }
                    condition.notify_one();
                    throw std::runtime_error("callback failure");
                }));

            REQUIRE(httpClient.performRequest(
                secondRequest,
                [&](const HttpResponsePtr& response)
                {
                    secondErrorCode = response ? response->errorCode : HttpErrorCode::Invalid;
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        secondCallbackCalled = true;
                    }
                    condition.notify_one();
                }));

            std::unique_lock<std::mutex> lock(mutex);
            REQUIRE(condition.wait_for(lock, std::chrono::seconds(2), [&] {
                return firstCallbackCalled && secondCallbackCalled;
            }));

            REQUIRE(firstErrorCode == HttpErrorCode::UrlMalformed);
            REQUIRE(secondErrorCode == HttpErrorCode::UrlMalformed);
        }

        SECTION("parseHttpHeaders rejects header lines without colon")
        {
            auto socket = std::unique_ptr<Socket>(
                new ScriptedSocket("Host: example.com\r\nMalformedHeader\r\n\r\n"));

            auto headers = parseHttpHeaders(socket, nullptr);

            REQUIRE(!headers);
        }

        SECTION("parseHttpHeaders rejects duplicate singleton headers")
        {
            auto socket = std::unique_ptr<Socket>(
                new ScriptedSocket("Host: example.com\r\nHost: attacker.example\r\n\r\n"));

            auto headers = parseHttpHeaders(socket, nullptr);

            REQUIRE(!headers);
        }

        SECTION("parseHttpHeaders combines duplicate list headers")
        {
            auto socket = std::unique_ptr<Socket>(
                new ScriptedSocket("Connection: keep-alive\r\nConnection: Upgrade\r\n\r\n"));

            auto headers = parseHttpHeaders(socket, nullptr);

            REQUIRE(headers);
            REQUIRE((*headers)["Connection"] == "keep-alive, Upgrade");
        }

        SECTION("parseHttpHeaders accepts identical duplicate Content-Length")
        {
            auto socket = std::unique_ptr<Socket>(
                new ScriptedSocket("Content-Length: 3\r\nContent-Length: 3\r\n\r\n"));

            auto headers = parseHttpHeaders(socket, nullptr);

            REQUIRE(headers);
            REQUIRE((*headers)["Content-Length"] == "3");
        }

        SECTION("parseHttpHeaders preserves first duplicate Set-Cookie")
        {
            auto socket = std::unique_ptr<Socket>(
                new ScriptedSocket("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"));

            auto headers = parseHttpHeaders(socket, nullptr);

            REQUIRE(headers);
            REQUIRE((*headers)["Set-Cookie"] == "a=1");
        }

        SECTION("HttpClient rejects unsupported protocols")
        {
            HttpClient httpClient;

            auto response = httpClient.get("ftp://example.com:21/", nullptr);

            REQUIRE(response->errorCode == HttpErrorCode::UrlMalformed);
            REQUIRE(response->errorMsg.find("Unsupported HTTP protocol") != std::string::npos);
        }

        SECTION("WebSocket rejects unsupported protocols")
        {
            WebSocket webSocket;
            webSocket.setUrl("http://example.com/");

            auto status = webSocket.connect(0);

            REQUIRE(!status.success);
            REQUIRE(status.errorStr.find("Unsupported WebSocket protocol") != std::string::npos);
        }

        SECTION("WebSocket start serializes concurrent callers")
        {
            WebSocket webSocket;
            webSocket.setUrl("http://example.com/");
            webSocket.setAutomaticReconnection(false);

            std::vector<std::thread> starters;
            for (int i = 0; i < 16; ++i)
            {
                starters.emplace_back([&webSocket] { webSocket.start(); });
            }

            for (auto& starter : starters)
            {
                starter.join();
            }

            webSocket.stop();
            REQUIRE(webSocket.getReadyState() == ReadyState::Closed);

            webSocket.start();
            webSocket.stop();
            REQUIRE(webSocket.getReadyState() == ReadyState::Closed);
        }

        SECTION("Socket writeBytes succeeds for empty writes")
        {
            Socket socket;

            REQUIRE(socket.writeBytes(std::string(), nullptr));
        }

        SECTION("HttpConnectionPool enforces total connection limit")
        {
#ifdef _WIN32
            SUCCEED("socketpair-based connection pool test is skipped on Windows");
#else
            auto& pool = HttpConnectionPool::getInstance();
            pool.clear();
            pool.setMaxConnectionsPerHost(4);
            pool.setMaxTotalConnections(1);

            SocketTLSOptions tlsOptions;
            ProxyConfig proxyConfig;
            int peerOne = -1;
            int peerTwo = -1;

            pool.release(makeOpenSocket(peerOne),
                         "first.example",
                         80,
                         false,
                         tlsOptions,
                         proxyConfig);
            pool.release(makeOpenSocket(peerTwo),
                         "second.example",
                         80,
                         false,
                         tlsOptions,
                         proxyConfig);

            std::string errorMsg;
            auto reused = pool.acquire("second.example", 80, false, tlsOptions, proxyConfig, errorMsg);
            const bool reusedSecondConnection = reused && reused->isOpen();

            struct pollfd fds[1];
            fds[0].fd = peerOne;
            fds[0].events = POLLIN;
            fds[0].revents = 0;

            void* event = nullptr;
            const bool evictedFirstConnection =
                ix::poll(fds, 1, 100, &event) == 1 && (fds[0].revents & POLLIN) != 0;
            char byte = '\0';
            const auto peerOneBytes =
                evictedFirstConnection ? ::recv(peerOne, &byte, sizeof(byte), 0) : -1;

            reused.reset();
            Socket::closeSocket(peerOne);
            Socket::closeSocket(peerTwo);
            pool.setMaxTotalConnections(64);
            pool.clear();

            REQUIRE(evictedFirstConnection);
            REQUIRE(peerOneBytes == 0);
            REQUIRE(reusedSecondConnection);
#endif
        }

#ifdef IXWEBSOCKET_USE_ZLIB
        SECTION("gzip compression reports success explicitly")
        {
            std::string compressed;

            REQUIRE(gzipCompress("0123456789", compressed));
            REQUIRE(!compressed.empty());
        }

        SECTION("gzip decompression enforces output limit")
        {
            std::string compressed = gzipCompress("0123456789");
            std::string decompressed;

            REQUIRE(!gzipDecompress(compressed, decompressed, 9));
            REQUIRE(decompressed.empty());
            REQUIRE(gzipDecompress(compressed, decompressed, 10));
            REQUIRE(decompressed == "0123456789");
        }
#else
        SECTION("gzip compression reports unsupported without zlib")
        {
            std::string compressed("unchanged");

            REQUIRE(!gzipCompress("0123456789", compressed));
            REQUIRE(compressed.empty());
        }
#endif
    }

} // namespace ix
