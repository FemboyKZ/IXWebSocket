/*
 *  IXHttpClient.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone, Inc. All rights reserved.
 */

#include "IXHttpClient.h"

#include "IXBase64.h"
#include "IXStrCaseCompare.h"
#include "IXGzipCodec.h"
#include "IXHttpConnectionPool.h"
#include "IXSecureRandom.h"
#include "IXSocketFactory.h"
#include "IXUrlParser.h"
#include "IXUserAgent.h"
#include "IXWebSocketHttpHeaders.h"
#include <assert.h>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

namespace ix
{
    namespace
    {
        constexpr size_t kMaxHttpTrailerCount = 100;
        constexpr size_t kMaxHttpTrailerBytes = 64 * 1024;

        bool exceedsHttpBodySizeLimit(uint64_t currentSize, size_t bytesToAdd)
        {
            return bytesToAdd > kMaxHttpBodySize ||
                   currentSize > static_cast<uint64_t>(kMaxHttpBodySize - bytesToAdd);
        }

        bool isRedirectStatusCode(int code)
        {
            return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
        }

        bool isNoBodyStatusCode(int code)
        {
            return code == 204 || code == 205 || code == 304 || (code >= 100 && code < 200);
        }

        bool isSensitiveHttpHeaderForLogging(std::string_view name)
        {
            return ix::caseInsensitiveEquals(name, "authorization") ||
                   ix::caseInsensitiveEquals(name, "proxy-authorization") ||
                   ix::caseInsensitiveEquals(name, "cookie") ||
                   ix::caseInsensitiveEquals(name, "cookie2");
        }

        bool isRestrictedRequestHeaderName(std::string_view name)
        {
            return ix::caseInsensitiveEquals(name, "content-length") ||
                   ix::caseInsensitiveEquals(name, "transfer-encoding");
        }

        std::string redactHttpRequestTargetForLogging(std::string_view target)
        {
            auto sensitiveStart = target.find_first_of("?#");
            if (sensitiveStart == std::string_view::npos)
            {
                return std::string(target);
            }

            if (sensitiveStart == 0)
            {
                return "/";
            }

            return std::string(target.substr(0, sensitiveStart));
        }

        std::string redactHttpRequestLineForLogging(std::string_view line)
        {
            const auto firstSpace = line.find(' ');
            if (firstSpace == std::string_view::npos)
            {
                return std::string(line);
            }

            const auto secondSpace = line.find(' ', firstSpace + 1);
            if (secondSpace == std::string_view::npos)
            {
                return std::string(line);
            }

            std::string sanitized;
            sanitized.reserve(line.size());
            sanitized.append(line.data(), firstSpace + 1);
            sanitized += redactHttpRequestTargetForLogging(
                line.substr(firstSpace + 1, secondSpace - firstSpace - 1));
            sanitized.append(line.data() + secondSpace, line.size() - secondSpace);
            return sanitized;
        }

        bool shouldWriteExtraHeader(std::string_view name, bool forwardSensitiveHeaders)
        {
            if (forwardSensitiveHeaders)
            {
                return true;
            }

            return !isSensitiveHttpHeaderForLogging(name) && !ix::caseInsensitiveEquals(name, "host");
        }

        bool shouldForwardSensitiveHeaders(const std::string& fromUrl,
                                           const std::string& toUrl)
        {
            std::string fromProtocol;
            std::string fromHost;
            std::string fromPath;
            std::string fromQuery;
            int fromPort = 0;
            bool fromDefaultPort = false;

            std::string toProtocol;
            std::string toHost;
            std::string toPath;
            std::string toQuery;
            int toPort = 0;
            bool toDefaultPort = false;

            if (!UrlParser::parse(fromUrl,
                                  fromProtocol,
                                  fromHost,
                                  fromPath,
                                  fromQuery,
                                  fromPort,
                                  fromDefaultPort) ||
                !UrlParser::parse(
                    toUrl, toProtocol, toHost, toPath, toQuery, toPort, toDefaultPort))
            {
                return false;
            }

            return ix::caseInsensitiveEquals(fromProtocol, toProtocol) &&
                   ix::caseInsensitiveEquals(fromHost, toHost) && fromPort == toPort;
        }

        std::string escapeMultipartHeaderParameter(std::string_view value)
        {
            std::string escaped;
            escaped.reserve(value.size());

            for (char c : value)
            {
                unsigned char ch = static_cast<unsigned char>(c);
                if (c == '"' || c == '\\')
                {
                    escaped += '\\';
                    escaped += c;
                }
                else if (ch < 0x20 || ch == 0x7f)
                {
                    escaped += '_';
                }
                else
                {
                    escaped += c;
                }
            }

            return escaped;
        }

        std::string redactHttpRequestForLogging(
            const std::string& request,
            size_t bodySize = std::numeric_limits<size_t>::max())
        {
            const std::string headerTerminator("\r\n\r\n");
            size_t headerEnd = request.find(headerTerminator);
            if (headerEnd == std::string::npos)
            {
                return request;
            }

            std::stringstream sanitized;
            size_t lineStart = 0;
            while (lineStart < headerEnd)
            {
                size_t lineEnd = request.find("\r\n", lineStart);
                if (lineEnd == std::string::npos || lineEnd > headerEnd)
                {
                    lineEnd = headerEnd;
                }

                std::string_view line(request.data() + lineStart, lineEnd - lineStart);
                size_t colon = line.find(':');
                if (lineStart == 0)
                {
                    sanitized << redactHttpRequestLineForLogging(line) << "\r\n";
                }
                else if (colon != std::string_view::npos &&
                    isSensitiveHttpHeaderForLogging(line.substr(0, colon)))
                {
                    sanitized << line.substr(0, colon) << ": [redacted]\r\n";
                }
                else
                {
                    sanitized << line << "\r\n";
                }

                lineStart = lineEnd + 2;
            }

            sanitized << "\r\n";
            if (bodySize == std::numeric_limits<size_t>::max())
            {
                const size_t bodyStart = headerEnd + headerTerminator.size();
                bodySize = bodyStart < request.size() ? request.size() - bodyStart : 0;
            }

            if (bodySize > 0)
            {
                sanitized << "[request body redacted, " << bodySize << " bytes]";
            }

            return sanitized.str();
        }

        bool isDefaultHttpPort(const std::string& protocol, int port)
        {
            return (protocol == "http" && port == 80) || (protocol == "https" && port == 443);
        }

        void splitPathAndQuery(const std::string& value, std::string& path, std::string& query)
        {
            std::string withoutFragment = value.substr(0, value.find('#'));
            auto queryPos = withoutFragment.find('?');

            if (queryPos == std::string::npos)
            {
                path = withoutFragment;
                query.clear();
                return;
            }

            path = withoutFragment.substr(0, queryPos);
            query = withoutFragment.substr(queryPos + 1);
        }

        std::string normalizeUrlPath(const std::string& path)
        {
            std::vector<std::string> segments;

            size_t start = 0;
            while (start <= path.size())
            {
                size_t slashPos = path.find('/', start);
                size_t end = (slashPos == std::string::npos) ? path.size() : slashPos;

                std::string segment = path.substr(start, end - start);
                if (segment == "..")
                {
                    if (!segments.empty())
                    {
                        segments.pop_back();
                    }
                }
                else if (!segment.empty() && segment != ".")
                {
                    segments.emplace_back(segment);
                }

                if (slashPos == std::string::npos)
                {
                    break;
                }

                start = slashPos + 1;
            }

            std::string normalizedPath("/");
            for (size_t i = 0; i < segments.size(); ++i)
            {
                normalizedPath += segments[i];
                if (i + 1 != segments.size())
                {
                    normalizedPath += '/';
                }
            }

            if (path.size() > 1 && path.back() == '/' && normalizedPath.back() != '/')
            {
                normalizedPath += '/';
            }

            return normalizedPath;
        }

        bool resolveHttpRedirectUrl(const std::string& baseUrl,
                                    const std::string& location,
                                    std::string& resolvedUrl,
                                    std::string& errorMsg)
        {
            if (location.empty())
            {
                errorMsg = "Redirect Location header is empty";
                return false;
            }

            if (ix::caseInsensitiveStartsWith(location, "http://") ||
                ix::caseInsensitiveStartsWith(location, "https://"))
            {
                resolvedUrl = location;
                return true;
            }

            std::string protocol;
            std::string host;
            std::string path;
            std::string query;
            std::string username;
            std::string password;
            int port = 0;
            if (!ix::UrlParser::parse(baseUrl, protocol, host, path, query, port, username, password))
            {
                errorMsg = "Could not parse redirect base url: " + baseUrl;
                return false;
            }

            if (protocol != "http" && protocol != "https")
            {
                errorMsg = "Unsupported redirect base protocol: " + protocol;
                return false;
            }

            std::string basePathOnly;
            std::string ignoredBaseQuery;
            splitPathAndQuery(path, basePathOnly, ignoredBaseQuery);
            if (basePathOnly.empty())
            {
                basePathOnly = "/";
            }

            if (location.rfind("//", 0) == 0)
            {
                resolvedUrl = protocol + ":" + location;
                return true;
            }

            std::string resolvedPath;
            std::string resolvedQuery;

            if (location[0] == '/')
            {
                splitPathAndQuery(location, resolvedPath, resolvedQuery);
            }
            else if (location[0] == '?')
            {
                resolvedPath = basePathOnly;
                resolvedQuery = location.substr(1);
            }
            else if (location[0] == '#')
            {
                resolvedPath = basePathOnly;
                resolvedQuery = query;
            }
            else
            {
                std::string basePath = basePathOnly;
                auto slashPos = basePath.rfind('/');
                std::string directory = (slashPos == std::string::npos) ? "/" : basePath.substr(0, slashPos + 1);

                std::string merged = directory + location;
                splitPathAndQuery(merged, resolvedPath, resolvedQuery);
            }

            resolvedPath = normalizeUrlPath(resolvedPath.empty() ? "/" : resolvedPath);

            std::stringstream ss;
            ss << protocol << "://" << formatHttpHost(host);
            if (!isDefaultHttpPort(protocol, port))
            {
                ss << ":" << port;
            }
            ss << resolvedPath;
            if (!resolvedQuery.empty())
            {
                ss << "?" << resolvedQuery;
            }

            resolvedUrl = ss.str();
            return true;
        }

        bool parseChunkSizeLine(const std::string& chunkLine,
                                size_t& chunkSize,
                                std::string& errorMsg)
        {
            std::string_view chunkView(chunkLine);

            // readLine() returns a CRLF-terminated line.
            if (chunkView.size() >= 2 &&
                chunkView[chunkView.size() - 2] == '\r' &&
                chunkView[chunkView.size() - 1] == '\n')
            {
                chunkView.remove_suffix(2);
            }

            // Ignore chunk extensions per RFC 7230 section 4.1.
            const auto extensionPos = chunkView.find(';');
            if (extensionPos != std::string_view::npos)
            {
                chunkView = chunkView.substr(0, extensionPos);
            }

            // Trim optional whitespace.
            while (!chunkView.empty() &&
                   std::isspace(static_cast<unsigned char>(chunkView.front())))
            {
                chunkView.remove_prefix(1);
            }
            while (!chunkView.empty() &&
                   std::isspace(static_cast<unsigned char>(chunkView.back())))
            {
                chunkView.remove_suffix(1);
            }

            if (chunkView.empty())
            {
                errorMsg = "Invalid chunk size";
                return false;
            }

            uint64_t parsedChunkSize = 0;
            auto [ptr, ec] = std::from_chars(
                chunkView.data(), chunkView.data() + chunkView.size(), parsedChunkSize, 16);
            if (ec != std::errc() || ptr != chunkView.data() + chunkView.size())
            {
                errorMsg = "Invalid chunk size";
                return false;
            }

            if (parsedChunkSize > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
            {
                errorMsg = "Chunk size exceeds platform limits";
                return false;
            }

            chunkSize = static_cast<size_t>(parsedChunkSize);
            return true;
        }

        bool validateTrailerLine(const std::string& line)
        {
            auto colon = line.find(':');
            if (colon == std::string::npos || colon == 0)
            {
                return false;
            }

            size_t valueStart = colon + 1;
            while (valueStart < line.size() &&
                   (line[valueStart] == ' ' || line[valueStart] == '\t'))
            {
                ++valueStart;
            }

            size_t valueEnd = line.size();
            if (valueEnd >= 2 && line[valueEnd - 2] == '\r' && line[valueEnd - 1] == '\n')
            {
                valueEnd -= 2;
            }

            while (valueEnd > valueStart &&
                   std::isspace(static_cast<unsigned char>(line[valueEnd - 1])))
            {
                --valueEnd;
            }

            std::string_view name(line.data(), colon);
            std::string_view value(line.data() + valueStart, valueEnd - valueStart);
            return isValidHttpHeaderName(name) && isValidHttpHeaderValue(value);
        }

        template<typename ClassifyError>
        bool readAndDiscardChunkTrailers(Socket& socket,
                                         std::string trailerLine,
                                         const CancellationRequest& isCancellationRequested,
                                         const ClassifyError& classifyError,
                                         std::string& errorMsg,
                                         HttpErrorCode& errorCode)
        {
            size_t trailerCount = 0;
            size_t trailerBytes = 0;

            while (true)
            {
                if (trailerLine.size() > kMaxHttpTrailerBytes - trailerBytes)
                {
                    errorCode = HttpErrorCode::HeaderParsingError;
                    errorMsg = "Chunk trailers are too large";
                    return false;
                }
                trailerBytes += trailerLine.size();

                if (trailerLine == "\r\n")
                {
                    return true;
                }

                if (++trailerCount > kMaxHttpTrailerCount)
                {
                    errorCode = HttpErrorCode::HeaderParsingError;
                    errorMsg = "Chunk response has too many trailers";
                    return false;
                }

                if (!validateTrailerLine(trailerLine))
                {
                    errorCode = HttpErrorCode::HeaderParsingError;
                    errorMsg = "Invalid chunk trailer";
                    return false;
                }

                auto nextTrailerLine = socket.readLine(isCancellationRequested);
                if (!nextTrailerLine)
                {
                    errorCode = classifyError(HttpErrorCode::ChunkReadError);
                    errorMsg = "Cannot read chunk trailers";
                    return false;
                }
                trailerLine = std::move(*nextTrailerLine);
            }
        }

        template<typename ClassifyError>
        bool readChunkedBody(Socket& socket,
                             const HttpRequestArgsPtr& args,
                             const CancellationRequest& isCancellationRequested,
                             const ClassifyError& classifyError,
                             std::string& payload,
                             std::string& errorMsg,
                             HttpErrorCode& errorCode,
                             uint64_t& streamedDownloadSize)
        {
            while (true)
            {
                errorCode = classifyError(HttpErrorCode::ChunkReadError);

                auto chunkLine = socket.readLine(isCancellationRequested);
                if (!chunkLine)
                {
                    errorMsg = "Cannot read chunk size";
                    return false;
                }

                size_t chunkSize = 0;
                if (!parseChunkSizeLine(*chunkLine, chunkSize, errorMsg))
                {
                    errorCode = HttpErrorCode::HeaderParsingError;
                    return false;
                }

                if (args->verbose && args->logger)
                {
                    std::stringstream oss;
                    oss << "Reading " << chunkSize << " bytes" << std::endl;
                    args->logger(oss.str());
                }

                if (args->onChunkCallback)
                {
                    if (exceedsHttpBodySizeLimit(streamedDownloadSize, chunkSize))
                    {
                        errorCode = HttpErrorCode::CannotReadBody;
                        errorMsg = "Chunked download exceeds HTTP body limit";
                        return false;
                    }
                }
                else if (chunkSize > kMaxHttpBodySize - payload.size())
                {
                    errorCode = HttpErrorCode::CannotReadBody;
                    errorMsg = "Chunk aggregation exceeds HTTP body limit";
                    return false;
                }

                auto chunkResult = socket.readBytes(chunkSize,
                                                    args->onProgressCallback,
                                                    args->onChunkCallback,
                                                    isCancellationRequested);
                if (!chunkResult)
                {
                    errorCode = classifyError(HttpErrorCode::ChunkReadError);
                    errorMsg = "Cannot read chunk";
                    return false;
                }

                if (args->onChunkCallback)
                {
                    if (chunkSize > std::numeric_limits<uint64_t>::max() - streamedDownloadSize)
                    {
                        errorCode = HttpErrorCode::CannotReadBody;
                        errorMsg = "Chunked download size exceeds counter limits";
                        return false;
                    }
                    streamedDownloadSize += chunkSize;
                }
                else
                {
                    payload.reserve(payload.size() + chunkSize);
                    payload += *chunkResult;
                }

                auto termLine = socket.readLine(isCancellationRequested);
                if (!termLine)
                {
                    errorCode = classifyError(HttpErrorCode::ChunkReadError);
                    errorMsg = "Cannot read chunk terminator";
                    return false;
                }

                if (chunkSize == 0)
                {
                    if (!readAndDiscardChunkTrailers(socket,
                                                     std::move(*termLine),
                                                     isCancellationRequested,
                                                     classifyError,
                                                     errorMsg,
                                                     errorCode))
                    {
                        return false;
                    }
                    break;
                }

                if (*termLine != "\r\n")
                {
                    errorCode = HttpErrorCode::ChunkReadError;
                    errorMsg = "Invalid chunk terminator";
                    return false;
                }
            }

            return true;
        }

        template<typename ClassifyError>
        bool readCloseDelimitedBody(Socket& socket,
                                    const HttpRequestArgsPtr& args,
                                    const CancellationRequest& isCancellationRequested,
                                    const ClassifyError& classifyError,
                                    std::string& payload,
                                    std::string& errorMsg,
                                    HttpErrorCode& errorCode,
                                    uint64_t& streamedDownloadSize)
        {
            std::array<uint8_t, 1 << 14> readBuffer;

            while (true)
            {
                if (isCancellationRequested && isCancellationRequested())
                {
                    errorCode = classifyError(HttpErrorCode::ChunkReadError);
                    errorMsg = "Cannot read close-delimited body";
                    return false;
                }

                auto result = socket.recv(reinterpret_cast<char*>(readBuffer.data()), readBuffer.size());
                if (result)
                {
                    if (args->onChunkCallback)
                    {
                        if (exceedsHttpBodySizeLimit(streamedDownloadSize, result.bytes))
                        {
                            errorCode = HttpErrorCode::CannotReadBody;
                            errorMsg = "Close-delimited download exceeds HTTP body limit";
                            return false;
                        }

                        std::string chunk(reinterpret_cast<char*>(readBuffer.data()), result.bytes);
                        args->onChunkCallback(chunk);
                        streamedDownloadSize += result.bytes;
                    }
                    else
                    {
                        if (result.bytes > kMaxHttpBodySize - payload.size())
                        {
                            errorCode = HttpErrorCode::CannotReadBody;
                            errorMsg = "Close-delimited body exceeds HTTP body limit";
                            return false;
                        }

                        payload.append(reinterpret_cast<char*>(readBuffer.data()), result.bytes);
                    }

                    if (args->onProgressCallback &&
                        !args->onProgressCallback(args->onChunkCallback
                                                       ? streamedDownloadSize
                                                       : static_cast<uint64_t>(payload.size()),
                                                   0))
                    {
                        errorCode = HttpErrorCode::Cancelled;
                        errorMsg = "Close-delimited body read cancelled";
                        return false;
                    }

                    continue;
                }

                if (result.closed())
                {
                    return true;
                }

                if (result.wouldBlock())
                {
                    PollResultType pollResult = socket.isReadyToRead(100);
                    if (pollResult != PollResultType::Error)
                    {
                        continue;
                    }
                }

                errorCode = classifyError(HttpErrorCode::ChunkReadError);
                errorMsg = "Cannot read close-delimited body";
                return false;
            }
        }
    } // namespace

    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
    const std::string HttpClient::kPost = "POST";
    const std::string HttpClient::kGet = "GET";
    const std::string HttpClient::kHead = "HEAD";
    const std::string HttpClient::kDelete = "DELETE";
    const std::string HttpClient::kPut = "PUT";
    const std::string HttpClient::kPatch = "PATCH";

    HttpClient::HttpClient(bool async)
        : _async(async)
        , _stop(false)
        , _forceBody(false)
    {
        if (!_async) return;

        _thread = std::thread(&HttpClient::run, this);
    }

    HttpClient::~HttpClient()
    {
        if (!_thread.joinable()) return;

        _stop = true;
        _condition.notify_one();
        _thread.join();
    }

    void HttpClient::setTLSOptions(const SocketTLSOptions& tlsOptions)
    {
        std::lock_guard<std::recursive_mutex> lock(_mutex);
        _tlsOptions = tlsOptions;
    }

    void HttpClient::setProxyConfig(const ProxyConfig& proxyConfig)
    {
        std::lock_guard<std::recursive_mutex> lock(_mutex);
        _proxyConfig = proxyConfig;
    }

    void HttpClient::setForceBody(bool value)
    {
        std::lock_guard<std::recursive_mutex> lock(_mutex);
        _forceBody = value;
    }

    HttpRequestArgsPtr HttpClient::createRequest(const std::string& url, const std::string& verb)
    {
        auto request = std::make_shared<HttpRequestArgs>();
        request->url = url;
        request->verb = verb;
        return request;
    }

    bool HttpClient::performRequest(HttpRequestArgsPtr args,
                                    const OnResponseCallback& onResponseCallback)
    {
        assert(_async && "HttpClient needs its async parameter set to true "
                         "in order to call performRequest");
        if (!_async) return false;
        if (!args || !onResponseCallback) return false;

        // Enqueue the task
        {
            // acquire lock
            std::unique_lock<std::mutex> lock(_queueMutex);

            // add the task
            _queue.push(std::make_pair(args, onResponseCallback));
        } // release lock

        // wake up one thread
        _condition.notify_one();

        return true;
    }

    void HttpClient::run()
    {
        while (true)
        {
            HttpRequestArgsPtr args;
            OnResponseCallback onResponseCallback;

            {
                std::unique_lock<std::mutex> lock(_queueMutex);

                while (!_stop && _queue.empty())
                {
                    _condition.wait(lock);
                }

                if (_stop) return;

                auto [queuedArgs, queuedCallback] = _queue.front();
                _queue.pop();

                args = queuedArgs;
                onResponseCallback = queuedCallback;
            }

            if (_stop) return;
            if (!args || !onResponseCallback) continue;

            HttpResponsePtr response = request(args->url, args->verb, args->body, args);
            try
            {
                onResponseCallback(response);
            }
            catch (const std::exception&)
            {
            }
            catch (...)
            {
            }

            if (_stop) return;
        }
    }

    HttpResponsePtr HttpClient::request(const std::string& url,
                                        const std::string& verb,
                                        const std::string& body,
                                        HttpRequestArgsPtr args,
                                        int redirects,
                                        bool forwardSensitiveHeaders)
    {
        if (!args)
        {
            args = createRequest(url, verb);
        }

        // We only have one socket connection, so we cannot
        // make multiple requests concurrently.
        std::lock_guard<std::recursive_mutex> lock(_mutex);

        uint64_t uploadSize = 0;
        uint64_t downloadSize = 0;
        int code = 0;
        WebSocketHttpHeaders headers;
        std::string payload;
        std::string description;

        std::string protocol, host, path, query;
        int port;
        bool isProtocolDefaultPort;

        auto makeErrorResponse = [&](HttpErrorCode errorCode, const std::string& errorMsg) {
            return std::make_shared<HttpResponse>(code,
                                                  description,
                                                  errorCode,
                                                  headers,
                                                  payload,
                                                  errorMsg,
                                                  uploadSize,
                                                  downloadSize);
        };
        auto makeErrorResponseAndDiscardConnection =
            [&](HttpErrorCode errorCode, const std::string& errorMsg) {
                _socket.reset();
                return makeErrorResponse(errorCode, errorMsg);
            };

        if (!UrlParser::parse(url, protocol, host, path, query, port, isProtocolDefaultPort))
        {
            std::stringstream ss;
            ss << "Cannot parse url: " << url;
            return makeErrorResponse(HttpErrorCode::UrlMalformed, ss.str());
        }

        if (!isValidHttpHeaderName(verb))
        {
            return makeErrorResponse(HttpErrorCode::HeaderParsingError, "Invalid HTTP method");
        }

        if (protocol != "http" && protocol != "https")
        {
            return makeErrorResponse(HttpErrorCode::UrlMalformed,
                                     "Unsupported HTTP protocol: " + protocol);
        }

        if (!isValidHttpAuthority(host))
        {
            return makeErrorResponse(HttpErrorCode::UrlMalformed, "Invalid HTTP host");
        }

        if (!isValidHttpRequestTarget(path))
        {
            return makeErrorResponse(HttpErrorCode::UrlMalformed, "Invalid HTTP request target");
        }

        for (const auto& [name, value] : args->extraHeaders)
        {
            if (!isValidHttpHeaderName(name) || !isValidHttpHeaderValue(value))
            {
                return makeErrorResponse(HttpErrorCode::HeaderParsingError,
                                         "Invalid HTTP header: " + name);
            }

            if (isRestrictedRequestHeaderName(name))
            {
                return makeErrorResponse(HttpErrorCode::HeaderParsingError,
                                         "Restricted HTTP header: " + name);
            }
        }

        if (args->extraHeaders.find("User-Agent") == args->extraHeaders.end() &&
            !isValidHttpHeaderValue(userAgent()))
        {
            return makeErrorResponse(HttpErrorCode::HeaderParsingError,
                                     "Invalid default User-Agent header value");
        }

        if (args->authType == HttpAuthType::Bearer &&
            !isValidHttpHeaderValue(args->authToken))
        {
            return makeErrorResponse(HttpErrorCode::HeaderParsingError,
                                     "Invalid Authorization header value");
        }

        if (!args->multipartBoundary.empty() &&
            !isValidHttpHeaderValue(args->multipartBoundary))
        {
            return makeErrorResponse(HttpErrorCode::HeaderParsingError,
                                     "Invalid multipart boundary");
        }

        bool tls = protocol == "https";
        std::string errorMsg;

        const bool hasRequestBody = verb == kPost || verb == kPut || verb == kPatch || _forceBody;
        std::string requestBody(body);
        if (hasRequestBody && args->compressRequest)
        {
#ifdef IXWEBSOCKET_USE_ZLIB
            std::string compressedRequestBody;
            if (!gzipCompress(requestBody, compressedRequestBody))
            {
                return makeErrorResponse(HttpErrorCode::Gzip, "Error compressing request body");
            }
            requestBody = std::move(compressedRequestBody);
#else
            return makeErrorResponse(HttpErrorCode::Gzip,
                                     "ixwebsocket was not compiled with gzip support on");
#endif
        }

        auto releaseOrCloseConnection = [&]() {
            bool serverClose = headerContainsTokenCaseInsensitive(headers, "Connection", "close");

            if (serverClose || !_keepAlive)
            {
                _socket.reset();
            }
            else if (_useConnectionPool && _socket)
            {
                // Release reusable keep-alive connections to the shared pool.
                HttpConnectionPool::getInstance().release(
                    std::move(_socket), host, port, tls, _tlsOptions, _proxyConfig);
            }
        };

        // Check if we can reuse the existing connection
        bool canReuse = _keepAlive.load() && _socket && _socket->isOpen() &&
                        isConnectionReusable(host, port, tls);

        if (!canReuse)
        {
            _socket.reset();
            if (_useConnectionPool.load())
            {
                _socket = HttpConnectionPool::getInstance().acquire(
                    host, port, tls, _tlsOptions, _proxyConfig, errorMsg);
            }
            else
            {
                _socket = createSocket(tls, -1, errorMsg, _tlsOptions);
            }

            if (!_socket)
            {
                return std::make_shared<HttpResponse>(code,
                                                      description,
                                                      HttpErrorCode::CannotCreateSocket,
                                                      headers,
                                                      payload,
                                                      errorMsg,
                                                      uploadSize,
                                                      downloadSize);
            }

            if (_socket->isOpen())
            {
                canReuse = true;
                _lastHost = host;
                _lastPort = port;
                _lastTls = tls;
            }
            else
            {
                _socket->setProxyConfig(_proxyConfig);
            }
        }

        // Build request string
        std::stringstream ss;
        ss << verb << " " << path << " HTTP/1.1\r\n";
        if (args->extraHeaders.find("Host") == args->extraHeaders.end() ||
            !forwardSensitiveHeaders)
        {
            ss << "Host: " << formatHttpHost(host);
            if (!isProtocolDefaultPort)
            {
                ss << ":" << port;
            }
            ss << "\r\n";
        }

#ifdef IXWEBSOCKET_USE_ZLIB
        if (args->compress && !args->onChunkCallback &&
            args->extraHeaders.find("Accept-Encoding") == args->extraHeaders.end())
        {
            ss << "Accept-Encoding: gzip"
               << "\r\n";
        }
#endif

        // Append extra headers
        for (const auto& [name, value] : args->extraHeaders)
        {
            if (!shouldWriteExtraHeader(name, forwardSensitiveHeaders))
            {
                continue;
            }

            ss << name << ": " << value << "\r\n";
        }

        // Set a default Accept header if none is present
        if (args->extraHeaders.find("Accept") == args->extraHeaders.end())
        {
            ss << "Accept: */*"
               << "\r\n";
        }

        // Set a default User agent if none is present
        if (args->extraHeaders.find("User-Agent") == args->extraHeaders.end())
        {
            ss << "User-Agent: " << userAgent() << "\r\n";
        }

        // Set an origin header if missing
        if (args->extraHeaders.find("Origin") == args->extraHeaders.end())
        {
            ss << "Origin: " << protocol << "://" << formatHttpHost(host) << ":" << port << "\r\n";
        }

        // Set Connection header for Keep-Alive
        if (args->extraHeaders.find("Connection") == args->extraHeaders.end())
        {
            ss << "Connection: " << (_keepAlive ? "keep-alive" : "close") << "\r\n";
        }

        // Set Authorization header if auth is configured
        if (forwardSensitiveHeaders &&
            args->extraHeaders.find("Authorization") == args->extraHeaders.end())
        {
            if (args->authType == HttpAuthType::Basic && !args->authUsername.empty())
            {
                std::string credentials = args->authUsername + ":" + args->authPassword;
                ss << "Authorization: Basic " << macaron::Base64::Encode(credentials) << "\r\n";
            }
            else if (args->authType == HttpAuthType::Bearer && !args->authToken.empty())
            {
                ss << "Authorization: Bearer " << args->authToken << "\r\n";
            }
        }

        if (hasRequestBody)
        {
            // Set request compression header
#ifdef IXWEBSOCKET_USE_ZLIB
            if (args->compressRequest)
            {
                ss << "Content-Encoding: gzip"
                   << "\r\n";
            }
#endif

            ss << "Content-Length: " << requestBody.size() << "\r\n";

            // Set default Content-Type if unspecified
            if (args->extraHeaders.find("Content-Type") == args->extraHeaders.end())
            {
                if (args->multipartBoundary.empty())
                {
                    ss << "Content-Type: application/x-www-form-urlencoded"
                       << "\r\n";
                }
                else
                {
                    ss << "Content-Type: multipart/form-data; boundary=" << args->multipartBoundary
                       << "\r\n";
                }
            }
            ss << "\r\n";
        }
        else
        {
            ss << "\r\n";
        }

        std::string requestHeaders(ss.str());
        const uint64_t requestSize =
            static_cast<uint64_t>(requestHeaders.size()) + static_cast<uint64_t>(requestBody.size());
        std::string errMsg;

        // Make a cancellation object dealing with connection timeout
        auto cancelled = makeCancellationRequestWithTimeout(args->connectTimeout, args->cancel);
        enum class CancellationReason
        {
            None,
            Cancelled,
            Timeout
        };
        CancellationReason cancellationReason = CancellationReason::None;

        auto isCancellationRequested = [&]() {
            if (args->cancel.load() || _stop.load())
            {
                cancellationReason = CancellationReason::Cancelled;
                return true;
            }

            if (cancelled())
            {
                cancellationReason = CancellationReason::Timeout;
                return true;
            }

            return false;
        };

        auto classifyCancellation = [&](HttpErrorCode fallback) {
            if (cancellationReason == CancellationReason::Cancelled)
            {
                return HttpErrorCode::Cancelled;
            }

            if (cancellationReason == CancellationReason::Timeout)
            {
                return HttpErrorCode::Timeout;
            }

            if (args->cancel.load() || _stop.load())
            {
                return HttpErrorCode::Cancelled;
            }

            return fallback;
        };

        // Connect only if we don't have a reusable connection
        if (!canReuse)
        {
            bool success = _socket->connect(host, port, errMsg, isCancellationRequested);

            if (!success)
            {
                auto errorCode = classifyCancellation(HttpErrorCode::CannotConnect);
                std::stringstream ss;
                ss << "Cannot connect to url: " << url << " / error : " << errMsg;
                return makeErrorResponseAndDiscardConnection(errorCode, ss.str());
            }

            // Save connection info for potential reuse
            _lastHost = host;
            _lastPort = port;
            _lastTls = tls;
        }

        // Make a new cancellation object dealing with transfer timeout
        cancelled = makeCancellationRequestWithTimeout(args->transferTimeout, args->cancel);

        if (args->verbose)
        {
            std::stringstream ss;
            ss << "Sending " << verb << " request "
               << "to " << host << ":" << port << std::endl
               << "request size: " << requestSize << " bytes" << std::endl
               << "=============" << std::endl
               << redactHttpRequestForLogging(requestHeaders, requestBody.size())
               << "=============" << std::endl
               << std::endl;

            log(ss.str(), args);
        }

        if (!_socket->writeBytes(requestHeaders, isCancellationRequested) ||
            (hasRequestBody && !requestBody.empty() &&
             !_socket->writeBytes(requestBody, isCancellationRequested)))
        {
            auto errorCode = classifyCancellation(HttpErrorCode::SendError);
            std::string errorMsg("Cannot send request");
            return makeErrorResponseAndDiscardConnection(errorCode, errorMsg);
        }

        uploadSize = requestSize;

        auto line = _socket->readLine(isCancellationRequested);
        if (!line)
        {
            auto errorCode = classifyCancellation(HttpErrorCode::CannotReadStatusLine);
            std::string errorMsg("Cannot retrieve status line");
            return makeErrorResponseAndDiscardConnection(errorCode, errorMsg);
        }

        if (args->verbose)
        {
            std::stringstream ss;
            ss << "Status line " << *line;
            log(ss.str(), args);
        }

        auto [httpVersion, parsedStatusCode, parsedDescription] =
            Http::parseStatusLineWithDescription(*line);
        if (httpVersion.rfind("HTTP/", 0) != 0 || parsedStatusCode < 100 ||
            parsedStatusCode > 999)
        {
            std::string errorMsg("Cannot parse response code from status line");
            return makeErrorResponseAndDiscardConnection(HttpErrorCode::MissingStatus, errorMsg);
        }
        code = parsedStatusCode;
        description = parsedDescription;

        auto result = parseHttpHeaders(_socket, isCancellationRequested);
        if (!result)
        {
            auto errorCode = classifyCancellation(HttpErrorCode::HeaderParsingError);
            std::string errorMsg("Cannot parse http headers");
            return makeErrorResponseAndDiscardConnection(errorCode, errorMsg);
        }
        headers = *result;

        // Redirect ?
        if (isRedirectStatusCode(code) && args->followRedirects)
        {
            if (headers.find("Location") == headers.end())
            {
                std::string errorMsg("Missing location header for redirect");
                return makeErrorResponseAndDiscardConnection(HttpErrorCode::MissingLocation,
                                                             errorMsg);
            }

            if (redirects >= args->maxRedirects)
            {
                std::stringstream ss;
                ss << "Too many redirects: " << redirects;
                return makeErrorResponseAndDiscardConnection(HttpErrorCode::TooManyRedirects,
                                                             ss.str());
            }

            std::string location;
            std::string redirectErrorMsg;
            if (!resolveHttpRedirectUrl(url, headers["Location"], location, redirectErrorMsg))
            {
                return makeErrorResponseAndDiscardConnection(HttpErrorCode::UrlMalformed,
                                                             redirectErrorMsg);
            }

            _socket.reset();

            // HTTP spec: 301/302/303 should convert POST/PUT/PATCH to GET
            // 307/308 preserve the original method
            std::string redirectVerb = verb;
            std::string redirectBody = body;
            const bool redirectForwardSensitiveHeaders =
                forwardSensitiveHeaders && shouldForwardSensitiveHeaders(url, location);
            if (code == 301 || code == 302 || code == 303)
            {
                if (verb != kGet && verb != kHead)
                {
                    redirectVerb = kGet;
                    redirectBody.clear();
                }
            }

            return request(
                location, redirectVerb, redirectBody, args, redirects + 1, redirectForwardSensitiveHeaders);
        }

        if (verb == "HEAD")
        {
            releaseOrCloseConnection();
            return std::make_shared<HttpResponse>(code,
                                                  description,
                                                  HttpErrorCode::Ok,
                                                  headers,
                                                  payload,
                                                  std::string(),
                                                  uploadSize,
                                                  downloadSize);
        }

        // Parse response:
        auto contentLengthIt = headers.find("Content-Length");
        const bool chunkedTransferEncoding =
            headerContainsTokenCaseInsensitive(headers, "Transfer-Encoding", "chunked");
        if (isNoBodyStatusCode(code))
        {
            releaseOrCloseConnection();
            return std::make_shared<HttpResponse>(code,
                                                  description,
                                                  HttpErrorCode::Ok,
                                                  headers,
                                                  payload,
                                                  std::string(),
                                                  uploadSize,
                                                  downloadSize);
        }

        if (contentLengthIt != headers.end() && chunkedTransferEncoding)
        {
            return makeErrorResponseAndDiscardConnection(
                HttpErrorCode::HeaderParsingError,
                "HTTP response contains both Transfer-Encoding and Content-Length");
        }

        if (contentLengthIt != headers.end())
        {
            size_t contentLength = 0;
            if (!parseContentLengthHeader(contentLengthIt->second, contentLength, errorMsg))
            {
                return makeErrorResponseAndDiscardConnection(HttpErrorCode::HeaderParsingError,
                                                             errorMsg);
            }

            if (contentLength > kMaxHttpBodySize)
            {
                return makeErrorResponseAndDiscardConnection(HttpErrorCode::CannotReadBody,
                                                             "HTTP response body is too large");
            }

            auto chunkResult = _socket->readBytes(contentLength,
                                                  args->onProgressCallback,
                                                  args->onChunkCallback,
                                                  isCancellationRequested);
            if (!chunkResult)
            {
                auto errorCode = classifyCancellation(HttpErrorCode::ChunkReadError);
                errorMsg = "Cannot read chunk";
                return makeErrorResponseAndDiscardConnection(errorCode, errorMsg);
            }

            if (!args->onChunkCallback)
            {
                payload.reserve(contentLength);
                payload += *chunkResult;
            }
            else
            {
                downloadSize = contentLength;
            }
        }
        else if (chunkedTransferEncoding)
        {
            HttpErrorCode chunkReadError = HttpErrorCode::ChunkReadError;
            if (!readChunkedBody(*_socket,
                                 args,
                                 isCancellationRequested,
                                 classifyCancellation,
                                 payload,
                                 errorMsg,
                                 chunkReadError,
                                 downloadSize))
            {
                return makeErrorResponseAndDiscardConnection(chunkReadError, errorMsg);
            }
        }
        else
        {
            HttpErrorCode closeDelimitedReadError = HttpErrorCode::ChunkReadError;
            if (!readCloseDelimitedBody(*_socket,
                                        args,
                                        isCancellationRequested,
                                        classifyCancellation,
                                        payload,
                                        errorMsg,
                                        closeDelimitedReadError,
                                        downloadSize))
            {
                return makeErrorResponseAndDiscardConnection(closeDelimitedReadError, errorMsg);
            }
        }

        if (!args->onChunkCallback)
        {
            downloadSize = payload.size();
        }

        // If the content was compressed with gzip, decode it
        if (!args->onChunkCallback &&
            headerContainsTokenCaseInsensitive(headers, "Content-Encoding", "gzip"))
        {
#ifdef IXWEBSOCKET_USE_ZLIB
            std::string decompressedPayload;
            if (!gzipDecompress(payload, decompressedPayload, kMaxHttpBodySize))
            {
                std::string errorMsg("Error decompressing payload");
                return makeErrorResponseAndDiscardConnection(HttpErrorCode::Gzip, errorMsg);
            }
            payload = decompressedPayload;
#else
            std::string errorMsg("ixwebsocket was not compiled with gzip support on");
            return makeErrorResponseAndDiscardConnection(HttpErrorCode::Gzip, errorMsg);
#endif
        }

        releaseOrCloseConnection();

        return std::make_shared<HttpResponse>(code,
                                              description,
                                              HttpErrorCode::Ok,
                                              headers,
                                              payload,
                                              std::string(),
                                              uploadSize,
                                              downloadSize);
    }

    HttpResponsePtr HttpClient::get(const std::string& url, HttpRequestArgsPtr args)
    {
        return request(url, kGet, std::string(), args);
    }

    HttpResponsePtr HttpClient::head(const std::string& url, HttpRequestArgsPtr args)
    {
        return request(url, kHead, std::string(), args);
    }

    HttpResponsePtr HttpClient::Delete(const std::string& url, HttpRequestArgsPtr args)
    {
        return request(url, kDelete, std::string(), args);
    }

    HttpResponsePtr HttpClient::request(const std::string& url,
                                        const std::string& verb,
                                        const HttpParameters& httpParameters,
                                        const HttpFormDataParameters& httpFormDataParameters,
                                        HttpRequestArgsPtr args)
    {
        if (!args)
        {
            args = createRequest(url, verb);
        }

        std::string body;

        if (httpFormDataParameters.empty())
        {
            body = serializeHttpParameters(httpParameters);
        }
        else
        {
            std::string multipartBoundary = generateMultipartBoundary();
            if (multipartBoundary.empty())
            {
                return std::make_shared<HttpResponse>(0,
                                                      std::string(),
                                                      HttpErrorCode::Invalid,
                                                      WebSocketHttpHeaders(),
                                                      std::string(),
                                                      "Unable to generate multipart boundary");
            }

            args->multipartBoundary = multipartBoundary;
            body = serializeHttpFormDataParameters(
                multipartBoundary, httpFormDataParameters, httpParameters);
        }

        return request(url, verb, body, args);
    }

    HttpResponsePtr HttpClient::post(const std::string& url,
                                     const HttpParameters& httpParameters,
                                     const HttpFormDataParameters& httpFormDataParameters,
                                     HttpRequestArgsPtr args)
    {
        return request(url, kPost, httpParameters, httpFormDataParameters, args);
    }

    HttpResponsePtr HttpClient::post(const std::string& url,
                                     const std::string& body,
                                     HttpRequestArgsPtr args)
    {
        return request(url, kPost, body, args);
    }

    HttpResponsePtr HttpClient::put(const std::string& url,
                                    const HttpParameters& httpParameters,
                                    const HttpFormDataParameters& httpFormDataParameters,
                                    HttpRequestArgsPtr args)
    {
        return request(url, kPut, httpParameters, httpFormDataParameters, args);
    }

    HttpResponsePtr HttpClient::put(const std::string& url,
                                    const std::string& body,
                                    const HttpRequestArgsPtr args)
    {
        return request(url, kPut, body, args);
    }

    HttpResponsePtr HttpClient::patch(const std::string& url,
                                      const HttpParameters& httpParameters,
                                      const HttpFormDataParameters& httpFormDataParameters,
                                      HttpRequestArgsPtr args)
    {
        return request(url, kPatch, httpParameters, httpFormDataParameters, args);
    }

    HttpResponsePtr HttpClient::patch(const std::string& url,
                                      const std::string& body,
                                      const HttpRequestArgsPtr args)
    {
        return request(url, kPatch, body, args);
    }

    std::string HttpClient::urlEncode(const std::string& value)
    {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex;

        for (std::string::const_iterator i = value.begin(), n = value.end(); i != n; ++i)
        {
            unsigned char c = static_cast<unsigned char>(*i);

            // Keep alphanumeric and other accepted characters intact
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            {
                escaped << static_cast<char>(c);
                continue;
            }

            // Any other characters are percent-encoded
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char) c);
            escaped << std::nouppercase;
        }

        return escaped.str();
    }

    std::string HttpClient::serializeHttpParameters(const HttpParameters& httpParameters)
    {
        std::stringstream ss;
        size_t count = httpParameters.size();
        size_t i = 0;

        for (const auto& [key, val] : httpParameters)
        {
            ss << urlEncode(key) << "=" << urlEncode(val);

            if (i++ < (count - 1))
            {
                ss << "&";
            }
        }
        return ss.str();
    }

        std::string HttpClient::serializeHttpFormDataParameters(
            const std::string& multipartBoundary,
            const HttpFormDataParameters& httpFormDataParameters,
            const HttpParameters& httpParameters)
        {
            //
            // --AaB03x
            // Content-Disposition: form-data; name="submit-name"

            // Larry
            // --AaB03x
            // Content-Disposition: form-data; name="foo.txt"; filename="file1.txt"
            // Content-Type: text/plain

            // ... contents of file1.txt ...
            // --AaB03x--
            //
            std::stringstream ss;

            for (const auto& [name, content] : httpFormDataParameters)
            {
                std::string escapedName = escapeMultipartHeaderParameter(name);
                ss << "--" << multipartBoundary << "\r\n"
                   << "Content-Disposition:"
                   << " form-data; name=\"" << escapedName << "\";"
                   << " filename=\"" << escapedName << "\""
                   << "\r\n"
                   << "Content-Type: application/octet-stream"
                   << "\r\n"
                   << "\r\n"
                   << content << "\r\n";
            }

            for (const auto& [name, val] : httpParameters)
            {
                std::string escapedName = escapeMultipartHeaderParameter(name);
                ss << "--" << multipartBoundary << "\r\n"
                   << "Content-Disposition:"
                   << " form-data; name=\"" << escapedName << "\";"
                   << "\r\n"
                   << "\r\n"
                   << val << "\r\n";
            }

            ss << "--" << multipartBoundary << "--\r\n";

            return ss.str();
        }

    void HttpClient::log(const std::string& msg, HttpRequestArgsPtr args)
    {
        if (args->logger)
        {
            args->logger(msg);
        }
    }

    std::string HttpClient::generateMultipartBoundary()
    {
        static constexpr std::string_view kBoundaryChars =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        static constexpr size_t kBoundaryLength = 62;
        static constexpr uint8_t kUnbiasedByteLimit =
            static_cast<uint8_t>((256 / kBoundaryChars.size()) * kBoundaryChars.size());

        std::string boundary(kBoundaryLength, '\0');
        size_t offset = 0;

        while (offset < boundary.size())
        {
            uint8_t randomBytes[64] = {};
            if (!secureRandomBytes(randomBytes, sizeof(randomBytes)))
            {
                return std::string();
            }

            for (uint8_t value : randomBytes)
            {
                if (value >= kUnbiasedByteLimit)
                {
                    continue;
                }

                boundary[offset++] = kBoundaryChars[value % kBoundaryChars.size()];
                if (offset == boundary.size())
                {
                    break;
                }
            }
        }

        return boundary;
    }

    bool HttpClient::isConnectionReusable(const std::string& host, int port, bool tls) const
    {
        return _lastHost == host && _lastPort == port && _lastTls == tls;
    }

    void HttpClient::setKeepAlive(bool enabled)
    {
        _keepAlive.store(enabled);
    }

    void HttpClient::setUseConnectionPool(bool enabled)
    {
        _useConnectionPool.store(enabled);
    }

    bool HttpClient::isKeepAliveEnabled() const
    {
        return _keepAlive.load();
    }

    bool HttpClient::isUseConnectionPoolEnabled() const
    {
        return _useConnectionPool.load();
    }
} // namespace ix
