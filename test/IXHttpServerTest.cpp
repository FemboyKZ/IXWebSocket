/*
 *  IXSocketTest.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone. All rights reserved.
 */

#include "IXTest.h"
#include "catch.hpp"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <ixwebsocket/IXGetFreePort.h>
#include <ixwebsocket/IXGzipCodec.h>
#include <ixwebsocket/IXHttpClient.h>
#include <ixwebsocket/IXHttpServer.h>
#include <ixwebsocket/IXSocketServer.h>

namespace
{
    bool neverCancel()
    {
        return false;
    }

    void logHttpClientMessage(const std::string& msg)
    {
        std::string line = msg;
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
        {
            line.pop_back();
        }

        if (!line.empty())
        {
            ix::TLogger() << line;
        }
    }

    bool reportDownloadProgress(uint64_t current, uint64_t total)
    {
        if (total > 0 && current < total)
        {
            return true;
        }

        ix::TLogger() << "Downloaded " << current << " bytes out of " << total;
        return true;
    }

    bool readHttpRequest(std::unique_ptr<ix::Socket>& socket, std::string& requestLine)
    {
        auto line = socket->readLine(neverCancel);
        if (!line)
        {
            return false;
        }

        requestLine = *line;
        while (true)
        {
            line = socket->readLine(neverCancel);
            if (!line || *line == "\r\n")
            {
                return static_cast<bool>(line);
            }
        }
    }

    class RedirectKeepAliveServer final : public ix::SocketServer
    {
    public:
        explicit RedirectKeepAliveServer(int port)
            : SocketServer(port, "127.0.0.1")
        {
        }

    private:
        void writeRedirect(std::unique_ptr<ix::Socket>& socket)
        {
            const std::string body("redirect body must not be parsed as a status line");
            std::stringstream ss;
            ss << "HTTP/1.1 302 Found\r\n"
               << "Location: /target\r\n"
               << "Content-Length: " << body.size() << "\r\n"
               << "Connection: keep-alive\r\n"
               << "\r\n"
               << body;
            socket->writeBytes(ss.str(), neverCancel);
        }

        void writeTarget(std::unique_ptr<ix::Socket>& socket)
        {
            const std::string body("target ok");
            std::stringstream ss;
            ss << "HTTP/1.1 200 OK\r\n"
               << "Content-Length: " << body.size() << "\r\n"
               << "Connection: close\r\n"
               << "\r\n"
               << body;
            socket->writeBytes(ss.str(), neverCancel);
        }

        void writeNotFound(std::unique_ptr<ix::Socket>& socket)
        {
            const std::string body("not found");
            std::stringstream ss;
            ss << "HTTP/1.1 404 Not Found\r\n"
               << "Content-Length: " << body.size() << "\r\n"
               << "Connection: close\r\n"
               << "\r\n"
               << body;
            socket->writeBytes(ss.str(), neverCancel);
        }

        void handleConnection(std::unique_ptr<ix::Socket> socket,
                              std::shared_ptr<ix::ConnectionState> connectionState) final
        {
            std::string requestLine;
            if (!readHttpRequest(socket, requestLine))
            {
                connectionState->setTerminated();
                return;
            }

            if (requestLine.find(" /redirect ") != std::string::npos)
            {
                writeRedirect(socket);
                if (!readHttpRequest(socket, requestLine))
                {
                    connectionState->setTerminated();
                    return;
                }
            }

            if (requestLine.find(" /target ") != std::string::npos)
            {
                writeTarget(socket);
            }
            else
            {
                writeNotFound(socket);
            }

            connectionState->setTerminated();
        }

        size_t getConnectedClientsCount() final
        {
            return 0;
        }
    };

    class RawHttpResponseServer final : public ix::SocketServer
    {
    public:
        RawHttpResponseServer(int port, std::string response)
            : SocketServer(port, "127.0.0.1")
            , _response(std::move(response))
        {
        }

    private:
        void handleConnection(std::unique_ptr<ix::Socket> socket,
                              std::shared_ptr<ix::ConnectionState> connectionState) final
        {
            if (socket->readLine(neverCancel))
            {
                while (true)
                {
                    auto line = socket->readLine(neverCancel);
                    if (!line || *line == "\r\n")
                    {
                        break;
                    }
                }
            }

            socket->writeBytes(_response, neverCancel);
            connectionState->setTerminated();
        }

        size_t getConnectedClientsCount() final
        {
            return 0;
        }

        std::string _response;
    };

    class HangingBodyServer final : public ix::SocketServer
    {
    public:
        explicit HangingBodyServer(int port)
            : SocketServer(port, "127.0.0.1")
        {
        }

    private:
        void handleConnection(std::unique_ptr<ix::Socket> socket,
                              std::shared_ptr<ix::ConnectionState> connectionState) final
        {
            std::string requestLine;
            if (!readHttpRequest(socket, requestLine))
            {
                connectionState->setTerminated();
                return;
            }

            socket->writeBytes("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 4\r\n"
                               "Connection: close\r\n"
                               "\r\n",
                               neverCancel);
            ix::msleep(1500);
            connectionState->setTerminated();
        }

        size_t getConnectedClientsCount() final
        {
            return 0;
        }
    };
} // namespace

using namespace ix;

TEST_CASE("http server", "[httpd]")
{
    SECTION("Connect to a local HTTP server")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        WebSocketHttpHeaders headers;

        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/data/foo.txt";
        auto args = httpClient.createRequest(url);

        args->extraHeaders = headers;
        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->followRedirects = true;
        args->maxRedirects = 10;
        args->verbose = true;
        args->compress = true;
        args->logger = logHttpClientMessage;
        args->onProgressCallback = reportDownloadProgress;

        auto response = httpClient.get(url, args);

        for (auto it : response->headers)
        {
            std::cerr << it.first << ": " << it.second << std::endl;
        }

        std::cerr << "Upload size: " << response->uploadSize << std::endl;
        std::cerr << "Download size: " << response->downloadSize << std::endl;
        std::cerr << "Status: " << response->statusCode << std::endl;
        std::cerr << "Error message: " << response->errorMsg << std::endl;

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->headers.find("Accept-Encoding") == response->headers.end());
        REQUIRE(response->headers["Vary"] == "Accept-Encoding");
        REQUIRE(response->headers["Content-Encoding"] == "gzip");

        server.stop();
    }

    SECTION("Default static server does not reflect arbitrary Origin")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/data/foo.txt";
        auto args = httpClient.createRequest(url);
        args->extraHeaders["Origin"] = "https://attacker.example";

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->headers.find("Access-Control-Allow-Origin") ==
                response->headers.end());

        server.stop();
    }

    SECTION("Posting plain text data to a local HTTP server")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");

        server.setOnConnectionCallback(
            [](HttpRequestPtr request, std::shared_ptr<ConnectionState>) -> HttpResponsePtr {
                if (request->method == "POST")
                {
                    return std::make_shared<HttpResponse>(
                        200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), request->body);
                }

                return std::make_shared<HttpResponse>(400, "BAD REQUEST");
            });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        WebSocketHttpHeaders headers;
        headers["Content-Type"] = "text/plain";

        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        args->extraHeaders = headers;
        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->verbose = true;
        args->logger = logHttpClientMessage;
        args->body = "Hello World!";

        auto response = httpClient.post(url, args->body, args);

        std::cerr << "Status: " << response->statusCode << std::endl;
        std::cerr << "Error message: " << response->errorMsg << std::endl;
        std::cerr << "Body: " << response->body << std::endl;

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->body == args->body);

        server.stop();
    }

    SECTION("Verbose logging redacts authorization, request target query, and request body")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");

        server.setOnConnectionCallback(
            [](HttpRequestPtr request, std::shared_ptr<ConnectionState>) -> HttpResponsePtr {
                if (request->method == "POST")
                {
                    return std::make_shared<HttpResponse>(
                        200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), "ok");
                }

                return std::make_shared<HttpResponse>(400, "BAD REQUEST");
            });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/submit?access_token=query-secret";
        auto args = httpClient.createRequest(url);

        std::string logged;
        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->verbose = true;
        args->setBearerAuth("secret-token");
        args->logger = [&logged](const std::string& msg) { logged += msg; };

        auto response = httpClient.post(url, "secret body", args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(logged.find("secret-token") == std::string::npos);
        REQUIRE(logged.find("query-secret") == std::string::npos);
        REQUIRE(logged.find("secret body") == std::string::npos);
        REQUIRE(logged.find("POST /submit HTTP/1.1") != std::string::npos);
        REQUIRE(logged.find("POST /submit?access_token") == std::string::npos);
        REQUIRE(logged.find("Authorization: [redacted]") != std::string::npos);
        REQUIRE(logged.find("[request body redacted") != std::string::npos);

        server.stop();
    }

    SECTION("HTTP callback exceptions return 500")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");

        server.setOnConnectionCallback(
            [](HttpRequestPtr, std::shared_ptr<ConnectionState>) -> HttpResponsePtr {
                throw std::runtime_error("callback failure");
            });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);

        auto args = httpClient.createRequest(url);
        args->connectTimeout = 60;
        args->transferTimeout = 60;

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 500);

        server.stop();
    }

#ifdef IXWEBSOCKET_USE_ZLIB
    SECTION("Posting compressed raw body to a local HTTP server")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");

        server.setOnConnectionCallback(
            [](HttpRequestPtr request, std::shared_ptr<ConnectionState>) -> HttpResponsePtr {
                if (request->method == "POST" &&
                    headerContainsTokenCaseInsensitive(request->headers, "Content-Encoding", "gzip"))
                {
                    return std::make_shared<HttpResponse>(
                        200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), request->body);
                }

                return std::make_shared<HttpResponse>(400, "BAD REQUEST");
            });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        WebSocketHttpHeaders headers;
        headers["Content-Type"] = "text/plain";

        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        args->extraHeaders = headers;
        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->compressRequest = true;

        std::string body = "Hello compressed raw body!";
        auto response = httpClient.post(url, body, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->body == body);

        server.stop();
    }
#endif

    SECTION("Reject directory traversal paths")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/../CMakeLists.txt";

        auto args = httpClient.createRequest(url);
        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->followRedirects = false;

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 403);

        server.stop();
    }

    SECTION("Reject over-sized static files")
    {
        int port = getFreePort();
        const std::string fileName = "ix_http_server_too_large_" + std::to_string(port) + ".bin";
        struct RemoveFile
        {
            std::string path;
            ~RemoveFile()
            {
                std::remove(path.c_str());
            }
        } removeFile{fileName};

        {
            std::ofstream file(fileName, std::ios::binary);
            REQUIRE(file.is_open());
            file.seekp(64LL * 1024LL * 1024LL);
            file.put('\0');
            REQUIRE(file.good());
        }

        ix::HttpServer server(port, "127.0.0.1");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/";
        url += fileName;

        auto args = httpClient.createRequest(url);
        args->connectTimeout = 60;
        args->transferTimeout = 60;

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 413);

        server.stop();
    }

    SECTION("Reject static directory targets")
    {
        int port = getFreePort();
        const std::string directoryName = "ix_http_server_directory_" + std::to_string(port);
        struct RemoveDirectory
        {
            std::string path;
            ~RemoveDirectory()
            {
                std::error_code ec;
                std::filesystem::remove(path, ec);
            }
        } removeDirectory{directoryName};

        std::error_code ec;
        REQUIRE(std::filesystem::create_directory(directoryName, ec));

        ix::HttpServer server(port, "127.0.0.1");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/";
        url += directoryName;

        auto args = httpClient.createRequest(url);
        args->connectTimeout = 60;
        args->transferTimeout = 60;

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 404);

        server.stop();
    }

    SECTION("Serve static file byte ranges")
    {
        int port = getFreePort();
        const std::string fileName = "ix_http_server_range_" + std::to_string(port) + ".txt";
        struct RemoveFile
        {
            std::string path;
            ~RemoveFile()
            {
                std::remove(path.c_str());
            }
        } removeFile{fileName};

        {
            std::ofstream file(fileName, std::ios::binary);
            REQUIRE(file.is_open());
            file << "0123456789";
            REQUIRE(file.good());
        }

        ix::HttpServer server(port, "127.0.0.1");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/";
        url += fileName;

        auto args = httpClient.createRequest(url);
        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->extraHeaders["Range"] = "bytes=2-5";

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 206);
        REQUIRE(response->body == "2345");
        REQUIRE(response->headers["Content-Range"] == "bytes 2-5/10");
        REQUIRE(response->headers["Accept-Ranges"] == "bytes");
        REQUIRE(response->headers["ETag"].rfind("W/\"", 0) == 0);

        server.stop();
    }

    SECTION("Serve static file byte range metadata for HEAD")
    {
        int port = getFreePort();
        const std::string fileName =
            "ix_http_server_range_head_" + std::to_string(port) + ".txt";
        struct RemoveFile
        {
            std::string path;
            ~RemoveFile()
            {
                std::remove(path.c_str());
            }
        } removeFile{fileName};

        {
            std::ofstream file(fileName, std::ios::binary);
            REQUIRE(file.is_open());
            file << "0123456789";
            REQUIRE(file.good());
        }

        ix::HttpServer server(port, "127.0.0.1");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/";
        url += fileName;

        auto args = httpClient.createRequest(url);
        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->extraHeaders["Range"] = "bytes=-3";

        auto response = httpClient.head(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 206);
        REQUIRE(response->body.empty());
        REQUIRE(response->headers["Content-Length"] == "3");
        REQUIRE(response->headers["Content-Range"] == "bytes 7-9/10");

        server.stop();
    }
}

TEST_CASE("http client parsing", "[http]")
{
    SECTION("Escape multipart field names in Content-Disposition")
    {
        HttpClient httpClient;
        HttpFormDataParameters formData;
        formData["file\"\r\nInjected: x"] = "content";
        HttpParameters parameters;
        parameters["field\"\r\nInjected: y"] = "value";

        std::string serialized =
            httpClient.serializeHttpFormDataParameters("boundary", formData, parameters);

        REQUIRE(serialized.find("\r\nInjected: x") == std::string::npos);
        REQUIRE(serialized.find("\r\nInjected: y") == std::string::npos);
        REQUIRE(serialized.find("filename=\"file\\\"__Injected: x\"") != std::string::npos);
        REQUIRE(serialized.find("name=\"field\\\"__Injected: y\"") != std::string::npos);
    }

    SECTION("Reject invalid Content-Length response header")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: -1\r\n"
            "Connection: close\r\n"
            "\r\n");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::HeaderParsingError);
        REQUIRE(response->statusCode == 200);

        server.stop();
    }

    SECTION("Reject conflicting duplicate Content-Length response headers")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Content-Length: 4\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::HeaderParsingError);
        REQUIRE(response->statusCode == 200);

        server.stop();
    }

    SECTION("Reject response with both Transfer-Encoding and Content-Length")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "\r\n"
            "4\r\n"
            "pong\r\n"
            "0\r\n"
            "\r\n");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::HeaderParsingError);
        REQUIRE(response->statusCode == 200);

        server.stop();
    }

    SECTION("Reject oversized Content-Length before streaming response body")
    {
        int port = getFreePort();
        std::stringstream rawResponse;
        rawResponse << "HTTP/1.1 200 OK\r\n"
                    << "Content-Length: " << (kMaxHttpBodySize + 1) << "\r\n"
                    << "Connection: close\r\n"
                    << "\r\n";
        RawHttpResponseServer server(port, rawResponse.str());

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);
        bool chunkCallbackCalled = false;
        args->onChunkCallback = [&chunkCallbackCalled](const std::string&) {
            chunkCallbackCalled = true;
        };

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::CannotReadBody);
        REQUIRE(response->statusCode == 200);
        REQUIRE_FALSE(chunkCallbackCalled);

        server.stop();
    }

    SECTION("Parse chunked transfer-encoding regardless of value casing")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: Chunked\r\n"
            "Connection: close\r\n"
            "\r\n"
            "4\r\n"
            "pong\r\n"
            "0\r\n"
            "\r\n");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->body == "pong");

        server.stop();
    }

    SECTION("Read response body delimited by connection close")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.0 200 OK\r\n"
            "Connection: close\r\n"
            "\r\n"
            "close body");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->body == "close body");
        REQUIRE(response->downloadSize == 10);

        server.stop();
    }

    SECTION("Stream response body delimited by connection close")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.0 200 OK\r\n"
            "Connection: close\r\n"
            "\r\n"
            "streamed close body");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);
        std::string streamedBody;
        args->onChunkCallback = [&streamedBody](const std::string& chunk) {
            streamedBody += chunk;
        };

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->body.empty());
        REQUIRE(streamedBody == "streamed close body");
        REQUIRE(response->downloadSize == streamedBody.size());

        server.stop();
    }

    SECTION("Reject excessive chunked trailers")
    {
        int port = getFreePort();
        std::stringstream rawResponse;
        rawResponse << "HTTP/1.1 200 OK\r\n"
                    << "Transfer-Encoding: chunked\r\n"
                    << "Connection: close\r\n"
                    << "\r\n"
                    << "4\r\n"
                    << "pong\r\n"
                    << "0\r\n";
        for (int i = 0; i < 101; ++i)
        {
            rawResponse << "X-Trailer-" << i << ": value\r\n";
        }
        rawResponse << "\r\n";
        RawHttpResponseServer server(port, rawResponse.str());

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::HeaderParsingError);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->errorMsg == "Chunk response has too many trailers");

        server.stop();
    }

    SECTION("Reject malformed chunked trailers")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "\r\n"
            "4\r\n"
            "pong\r\n"
            "0\r\n"
            "MalformedTrailer\r\n"
            "\r\n");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::HeaderParsingError);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->errorMsg == "Invalid chunk trailer");

        server.stop();
    }

    SECTION("Reject oversized chunk before reading chunk body")
    {
        int port = getFreePort();
        std::stringstream rawResponse;
        rawResponse << "HTTP/1.1 200 OK\r\n"
                    << "Transfer-Encoding: chunked\r\n"
                    << "Connection: close\r\n"
                    << "\r\n"
                    << std::hex << (kMaxHttpBodySize + 1) << "\r\n";
        RawHttpResponseServer server(port, rawResponse.str());

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::CannotReadBody);
        REQUIRE(response->statusCode == 200);

        server.stop();
    }

    SECTION("Reject oversized chunk before streaming chunk body")
    {
        int port = getFreePort();
        std::stringstream rawResponse;
        rawResponse << "HTTP/1.1 200 OK\r\n"
                    << "Transfer-Encoding: chunked\r\n"
                    << "Connection: close\r\n"
                    << "\r\n"
                    << std::hex << (kMaxHttpBodySize + 1) << "\r\n";
        RawHttpResponseServer server(port, rawResponse.str());

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);
        bool chunkCallbackCalled = false;
        args->onChunkCallback = [&chunkCallbackCalled](const std::string&) {
            chunkCallbackCalled = true;
        };

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::CannotReadBody);
        REQUIRE(response->statusCode == 200);
        REQUIRE_FALSE(chunkCallbackCalled);

        server.stop();
    }

    SECTION("Report transfer timeout distinctly from read errors")
    {
        int port = getFreePort();
        HangingBodyServer server(port);

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);
        args->connectTimeout = 1;
        args->transferTimeout = 1;

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Timeout);
        REQUIRE(response->statusCode == 200);

        server.stop();
    }

    SECTION("Accept HTTP/1.0 status line")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->description == "OK");
        REQUIRE(response->body == "ok");

        server.stop();
    }

    SECTION("Preserve HTTP response reason phrase")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.1 418 I'm a teapot\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 418);
        REQUIRE(response->description == "I'm a teapot");

        server.stop();
    }

    SECTION("Treat 304 without body as valid response")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.1 304 Not Modified\r\n"
            "Connection: close\r\n"
            "\r\n");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 304);
        REQUIRE(response->body.empty());

        server.stop();
    }

    SECTION("Treat 304 with Content-Length metadata as a no-body response")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.1 304 Not Modified\r\n"
            "Content-Length: 12\r\n"
            "Connection: close\r\n"
            "\r\n");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 304);
        REQUIRE(response->body.empty());
        REQUIRE(response->downloadSize == 0);

        server.stop();
    }

    SECTION("Treat 205 without body as valid response")
    {
        int port = getFreePort();
        RawHttpResponseServer server(
            port,
            "HTTP/1.1 205 Reset Content\r\n"
            "Connection: close\r\n"
            "\r\n");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 205);
        REQUIRE(response->body.empty());

        server.stop();
    }

#ifdef IXWEBSOCKET_USE_ZLIB
    SECTION("Parse gzip content-encoding regardless of value casing")
    {
        std::string originalBody = "Hello Gzip";
        std::string compressedBody = gzipCompress(originalBody);

        std::ostringstream responseStream;
        responseStream << "HTTP/1.1 200 OK\r\n"
                       << "Content-Length: " << compressedBody.size() << "\r\n"
                       << "Content-Encoding: GZIP\r\n"
                       << "Connection: close\r\n"
                       << "\r\n";

        std::string rawResponse = responseStream.str();
        rawResponse += compressedBody;

        int port = getFreePort();
        RawHttpResponseServer server(port, std::move(rawResponse));

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->body == originalBody);

        server.stop();
    }

    SECTION("Stream gzip content without decompressing empty aggregate payload")
    {
        std::string originalBody = "Hello streamed gzip";
        std::string compressedBody = gzipCompress(originalBody);

        std::ostringstream responseStream;
        responseStream << "HTTP/1.1 200 OK\r\n"
                       << "Content-Length: " << compressedBody.size() << "\r\n"
                       << "Content-Encoding: gzip\r\n"
                       << "Connection: close\r\n"
                       << "\r\n";

        std::string rawResponse = responseStream.str();
        rawResponse += compressedBody;

        int port = getFreePort();
        RawHttpResponseServer server(port, std::move(rawResponse));

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        auto args = httpClient.createRequest(url);

        std::string streamedBody;
        args->onChunkCallback = [&streamedBody](const std::string& chunk) {
            streamedBody += chunk;
        };

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->body.empty());
        REQUIRE(response->downloadSize == compressedBody.size());
        REQUIRE(streamedBody == compressedBody);

        server.stop();
    }
#endif
}

TEST_CASE("http server redirection", "[httpd_redirect]")
{
    SECTION("Follow relative redirect without reusing unread redirect body")
    {
        int port = getFreePort();
        RedirectKeepAliveServer server(port);

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/redirect";
        auto args = httpClient.createRequest(url);

        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->followRedirects = true;
        args->maxRedirects = 10;

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->body == "target ok");

        server.stop();
    }

    SECTION("Follow query-only redirect without duplicating original query")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");

        server.setOnConnectionCallback(
            [](HttpRequestPtr request, std::shared_ptr<ConnectionState>) -> HttpResponsePtr {
                if (request->uri == "/redirect?old=1")
                {
                    WebSocketHttpHeaders headers;
                    headers["Location"] = "?new=1";
                    return std::make_shared<HttpResponse>(
                        302, "Found", HttpErrorCode::Ok, headers, "redirect");
                }

                if (request->uri == "/redirect?new=1")
                {
                    return std::make_shared<HttpResponse>(
                        200, "OK", HttpErrorCode::Ok, WebSocketHttpHeaders(), "query ok");
                }

                return std::make_shared<HttpResponse>(
                    404, "Not Found", HttpErrorCode::Ok, WebSocketHttpHeaders(), request->uri);
            });

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/redirect?old=1";
        auto args = httpClient.createRequest(url);

        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->followRedirects = true;
        args->maxRedirects = 10;

        auto response = httpClient.get(url, args);

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);
        REQUIRE(response->body == "query ok");

        server.stop();
    }

    SECTION(
        "Connect to a local HTTP server, with redirection enabled, but we do not follow redirects")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");
        server.makeRedirectServer("http://example.com");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        WebSocketHttpHeaders headers;

        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/data/foo.txt";
        auto args = httpClient.createRequest(url);

        args->extraHeaders = headers;
        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->followRedirects = false; // we dont want to follow redirect during testing
        args->maxRedirects = 10;
        args->verbose = true;
        args->compress = true;
        args->logger = logHttpClientMessage;
        args->onProgressCallback = reportDownloadProgress;

        auto response = httpClient.get(url, args);

        for (auto it : response->headers)
        {
            std::cerr << it.first << ": " << it.second << std::endl;
        }

        std::cerr << "Upload size: " << response->uploadSize << std::endl;
        std::cerr << "Download size: " << response->downloadSize << std::endl;
        std::cerr << "Status: " << response->statusCode << std::endl;
        std::cerr << "Error message: " << response->errorMsg << std::endl;

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 301);
        REQUIRE(response->headers["Location"] == "http://example.com");

        server.stop();
    }

    SECTION("Connect to a local HTTP server, with redirection enabled, but we do follow redirects")
    {
        int port = getFreePort();
        ix::HttpServer server(port, "127.0.0.1");
        server.makeRedirectServer("http://www.google.com");

        auto err = server.listen();
        REQUIRE(!err);
        server.start();

        HttpClient httpClient;
        WebSocketHttpHeaders headers;

        std::string url("http://127.0.0.1:");
        url += std::to_string(port);
        url += "/data/foo.txt";
        auto args = httpClient.createRequest(url);

        args->extraHeaders = headers;
        args->connectTimeout = 60;
        args->transferTimeout = 60;
        args->followRedirects = true;
        args->maxRedirects = 10;
        args->verbose = true;
        args->compress = true;
        args->logger = logHttpClientMessage;
        args->onProgressCallback = reportDownloadProgress;

        auto response = httpClient.get(url, args);

        for (auto it : response->headers)
        {
            std::cerr << it.first << ": " << it.second << std::endl;
        }

        std::cerr << "Upload size: " << response->uploadSize << std::endl;
        std::cerr << "Download size: " << response->downloadSize << std::endl;
        std::cerr << "Status: " << response->statusCode << std::endl;
        std::cerr << "Error message: " << response->errorMsg << std::endl;

        REQUIRE(response->errorCode == HttpErrorCode::Ok);
        REQUIRE(response->statusCode == 200);

        server.stop();
    }
}
