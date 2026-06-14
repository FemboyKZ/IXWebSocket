/*
 *  IXHttp.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone, Inc. All rights reserved.
 */

#pragma once

#include "IXProgressCallback.h"
#include "IXWebSocketHttpHeaders.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace ix
{
    enum class HttpErrorCode : int
    {
        Ok = 0,
        CannotConnect = 1,
        Timeout = 2,
        Gzip = 3,
        UrlMalformed = 4,
        CannotCreateSocket = 5,
        SendError = 6,
        ReadError = 7,
        CannotReadStatusLine = 8,
        MissingStatus = 9,
        HeaderParsingError = 10,
        MissingLocation = 11,
        TooManyRedirects = 12,
        ChunkReadError = 13,
        CannotReadBody = 14,
        Cancelled = 15,
        Invalid = 100
    };

    struct HttpResponse
    {
        int statusCode;
        std::string description;
        HttpErrorCode errorCode;
        WebSocketHttpHeaders headers;
        std::string body;
        std::string errorMsg;
        uint64_t uploadSize;
        uint64_t downloadSize;
        bool sendBody;

        HttpResponse(int s = 0,
                     const std::string& des = std::string(),
                     const HttpErrorCode& c = HttpErrorCode::Ok,
                     const WebSocketHttpHeaders& h = WebSocketHttpHeaders(),
                     const std::string& b = std::string(),
                     const std::string& e = std::string(),
                     uint64_t u = 0,
                     uint64_t d = 0,
                     bool sendBodyArg = true)
            : statusCode(s)
            , description(des)
            , errorCode(c)
            , headers(h)
            , body(b)
            , errorMsg(e)
            , uploadSize(u)
            , downloadSize(d)
            , sendBody(sendBodyArg)
        {
            ;
        }
    };

    using HttpResponsePtr = std::shared_ptr<HttpResponse>;
    using HttpParameters = std::unordered_map<std::string, std::string>;
    using HttpFormDataParameters = std::unordered_map<std::string, std::string>;
    using Logger = std::function<void(const std::string&)>;
    using OnResponseCallback = std::function<void(const HttpResponsePtr&)>;

    enum class HttpAuthType
    {
        None,
        Basic,
        Bearer
    };

    struct HttpRequestArgs
    {
        std::string url;
        std::string verb;
        WebSocketHttpHeaders extraHeaders;
        std::string body;
        std::string multipartBoundary;
        int connectTimeout = 60;
        int transferTimeout = 1800;
        bool followRedirects = true;
        int maxRedirects = 5;
        bool verbose = false;
        bool compress = true;
        bool compressRequest = false;
        Logger logger;
        OnProgressCallback onProgressCallback;
        OnChunkCallback onChunkCallback;
        std::atomic<bool> cancel{false};

        // Authentication
        HttpAuthType authType = HttpAuthType::None;
        std::string authUsername;
        std::string authPassword;  // For Basic auth
        std::string authToken;     // For Bearer auth

        void setBasicAuth(const std::string& username, const std::string& password)
        {
            authType = HttpAuthType::Basic;
            authUsername = username;
            authPassword = password;
        }

        void setBearerAuth(const std::string& token)
        {
            authType = HttpAuthType::Bearer;
            authToken = token;
        }
    };

    using HttpRequestArgsPtr = std::shared_ptr<HttpRequestArgs>;

    constexpr size_t kMaxHttpBodySize = 64ULL * 1024ULL * 1024ULL;

    struct HttpRequest
    {
        std::string uri;
        std::string method;
        std::string version;
        std::string body;
        WebSocketHttpHeaders headers;

        HttpRequest(const std::string& u,
                    const std::string& m,
                    const std::string& v,
                    const std::string& b,
                    const WebSocketHttpHeaders& h = WebSocketHttpHeaders())
            : uri(u)
            , method(m)
            , version(v)
            , body(b)
            , headers(h)
        {
        }
    };

    using HttpRequestPtr = std::shared_ptr<HttpRequest>;

    bool parseContentLengthHeader(std::string_view headerValue,
                                  int& contentLength,
                                  std::string& errorMsg);

    bool parseContentLengthHeader(std::string_view headerValue,
                                  size_t& contentLength,
                                  std::string& errorMsg);

    std::vector<std::string_view> splitHeaderTokens(std::string_view headerValue);

    bool headerContainsTokenCaseInsensitive(std::string_view headerValue,
                                            std::string_view token);

    bool headerContainsTokenCaseInsensitive(const WebSocketHttpHeaders& headers,
                                            const std::string& headerName,
                                            std::string_view token);

    std::string formatHttpHost(std::string_view host);

    bool isValidHttpHeaderName(std::string_view name);
    bool isValidHttpHeaderValue(std::string_view value);
    bool isValidHttpRequestTarget(std::string_view target);
    bool isValidHttpAuthority(std::string_view authority);
    bool parseHttpRequestLine(const std::string& line,
                              std::string& method,
                              std::string& uri,
                              std::string& httpVersion,
                              std::string& errorMsg);

    class Http
    {
    public:
        static std::tuple<bool, std::string, HttpRequestPtr> parseRequest(
            std::unique_ptr<Socket>& socket, int timeoutSecs);
        static bool sendResponse(HttpResponsePtr response, std::unique_ptr<Socket>& socket);
        static bool sendResponse(HttpResponsePtr response,
                                 std::unique_ptr<Socket>& socket,
                                 int timeoutSecs);

        static std::pair<std::string, int> parseStatusLine(const std::string& line);
        static std::tuple<std::string, int, std::string> parseStatusLineWithDescription(
            const std::string& line);
        static std::tuple<std::string, std::string, std::string> parseRequestLine(
            const std::string& line);
        static std::string trim(const std::string& str);
    };
} // namespace ix
