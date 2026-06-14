/*
 *  IXHttp.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone, Inc. All rights reserved.
 */

#include "IXHttp.h"

#include "IXCancellationRequest.h"
#include "IXGzipCodec.h"
#include "IXSocket.h"
#include "IXStrCaseCompare.h"
#include <charconv>
#include <cctype>
#include <limits>
#include <sstream>
#include <string_view>
#include <vector>

namespace ix
{
    namespace
    {
        std::string_view trimAsciiWhitespace(std::string_view value)
        {
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
            {
                value.remove_prefix(1);
            }

            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
            {
                value.remove_suffix(1);
            }

            return value;
        }

        std::string_view nextSpaceSeparatedToken(std::string_view value, size_t& cursor)
        {
            while (cursor < value.size() &&
                   std::isspace(static_cast<unsigned char>(value[cursor])))
            {
                ++cursor;
            }

            size_t start = cursor;
            while (cursor < value.size() &&
                   !std::isspace(static_cast<unsigned char>(value[cursor])))
            {
                ++cursor;
            }

            return value.substr(start, cursor - start);
        }

        bool parseIntToken(std::string_view token, int& value)
        {
            if (token.empty())
            {
                return false;
            }

            auto [ptr, ec] =
                std::from_chars(token.data(), token.data() + token.size(), value);
            return ec == std::errc() && ptr == token.data() + token.size();
        }

        bool parseContentLengthHeaderValue(std::string_view headerValue,
                                           uint64_t& parsedValue,
                                           std::string& errorMsg)
        {
            parsedValue = 0;
            auto [ptr, ec] =
                std::from_chars(headerValue.data(), headerValue.data() + headerValue.size(), parsedValue);

            if (ec != std::errc() || ptr != headerValue.data() + headerValue.size())
            {
                errorMsg = "Error parsing HTTP Header 'Content-Length'";
                return false;
            }

            return true;
        }

    } // namespace

    bool isValidHttpHeaderName(std::string_view name)
    {
        if (name.empty())
        {
            return false;
        }

        for (unsigned char c : name)
        {
            const bool alphaNum = std::isalnum(c) != 0;
            const bool symbol = c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
                                c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
                                c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
            if (!alphaNum && !symbol)
            {
                return false;
            }
        }

        return true;
    }

    bool isValidHttpHeaderValue(std::string_view value)
    {
        for (unsigned char c : value)
        {
            if (c == '\r' || c == '\n' || c == '\0' || c == 0x7f)
            {
                return false;
            }

            if (c < 0x20 && c != '\t')
            {
                return false;
            }
        }

        return true;
    }

    bool isValidHttpRequestTarget(std::string_view target)
    {
        if (target.empty())
        {
            return false;
        }

        for (unsigned char c : target)
        {
            if (c <= 0x20 || c == 0x7f)
            {
                return false;
            }
        }

        return true;
    }

    bool isValidHttpAuthority(std::string_view authority)
    {
        if (authority.empty())
        {
            return false;
        }

        for (unsigned char c : authority)
        {
            if (c <= 0x20 || c == 0x7f || c == '/' || c == '\\')
            {
                return false;
            }
        }

        return true;
    }

    bool parseHttpRequestLine(const std::string& line,
                              std::string& method,
                              std::string& uri,
                              std::string& httpVersion,
                              std::string& errorMsg)
    {
        method.clear();
        uri.clear();
        httpVersion.clear();

        std::string_view lineView = trimAsciiWhitespace(line);
        size_t cursor = 0;

        auto methodToken = nextSpaceSeparatedToken(lineView, cursor);
        auto uriToken = nextSpaceSeparatedToken(lineView, cursor);
        auto versionToken = nextSpaceSeparatedToken(lineView, cursor);

        while (cursor < lineView.size() &&
               std::isspace(static_cast<unsigned char>(lineView[cursor])))
        {
            ++cursor;
        }

        if (methodToken.empty() || uriToken.empty() || versionToken.empty() ||
            cursor != lineView.size())
        {
            errorMsg = "Invalid HTTP request line";
            return false;
        }

        if (!isValidHttpHeaderName(methodToken))
        {
            errorMsg = "Invalid HTTP method";
            return false;
        }

        if (!isValidHttpRequestTarget(uriToken))
        {
            errorMsg = "Invalid HTTP request target";
            return false;
        }

        if (versionToken != "HTTP/1.0" && versionToken != "HTTP/1.1")
        {
            errorMsg = "Invalid HTTP version";
            return false;
        }

        method = std::string(methodToken);
        uri = std::string(uriToken);
        httpVersion = std::string(versionToken);
        return true;
    }

    bool parseContentLengthHeader(std::string_view headerValue,
                                  int& contentLength,
                                  std::string& errorMsg)
    {
        uint64_t parsedValue = 0;
        if (!parseContentLengthHeaderValue(headerValue, parsedValue, errorMsg))
        {
            return false;
        }

        if (parsedValue > static_cast<uint64_t>(std::numeric_limits<int>::max()))
        {
            errorMsg = "Error: 'Content-Length' value was above max";
            return false;
        }

        contentLength = static_cast<int>(parsedValue);
        return true;
    }

    bool parseContentLengthHeader(std::string_view headerValue,
                                  size_t& contentLength,
                                  std::string& errorMsg)
    {
        uint64_t parsedValue = 0;
        if (!parseContentLengthHeaderValue(headerValue, parsedValue, errorMsg))
        {
            return false;
        }

        if (parsedValue > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
        {
            errorMsg = "Content-Length value exceeds platform limits";
            return false;
        }

        contentLength = static_cast<size_t>(parsedValue);
        return true;
    }

    std::string formatHttpHost(std::string_view host)
    {
        if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
        {
            return std::string(host);
        }

        if (host.find(':') != std::string_view::npos)
        {
            std::string bracketedHost("[");
            bracketedHost.append(host.data(), host.size());
            bracketedHost += ']';
            return bracketedHost;
        }

        return std::string(host);
    }

    std::vector<std::string_view> splitHeaderTokens(std::string_view headerValue)
    {
        std::vector<std::string_view> tokens;
        size_t start = 0;

        while (start < headerValue.size())
        {
            size_t commaPos = headerValue.find(',', start);
            size_t end = (commaPos == std::string_view::npos) ? headerValue.size() : commaPos;

            auto candidate = trimAsciiWhitespace(headerValue.substr(start, end - start));
            size_t parameterPos = candidate.find(';');
            if (parameterPos != std::string_view::npos)
            {
                candidate = trimAsciiWhitespace(candidate.substr(0, parameterPos));
            }

            if (!candidate.empty())
            {
                tokens.emplace_back(candidate);
            }

            if (commaPos == std::string_view::npos)
            {
                break;
            }

            start = commaPos + 1;
        }

        return tokens;
    }

    bool headerContainsTokenCaseInsensitive(std::string_view headerValue,
                                            std::string_view token)
    {
        const auto tokens = splitHeaderTokens(headerValue);
        for (const auto& candidate : tokens)
        {
            if (caseInsensitiveEquals(candidate, token))
            {
                return true;
            }
        }

        return false;
    }

    bool headerContainsTokenCaseInsensitive(const WebSocketHttpHeaders& headers,
                                            const std::string& headerName,
                                            std::string_view token)
    {
        auto it = headers.find(headerName);
        if (it == headers.end())
        {
            return false;
        }

        return headerContainsTokenCaseInsensitive(it->second, token);
    }

    std::string Http::trim(const std::string& str)
    {
        std::string out;
        out.reserve(str.size());
        for (char c : str)
        {
            if (c != ' ' && c != '\n' && c != '\r')
            {
                out += c;
            }
        }

        return out;
    }

    std::pair<std::string, int> Http::parseStatusLine(const std::string& line)
    {
        auto [httpVersion, statusCode, description] = parseStatusLineWithDescription(line);
        return std::make_pair(httpVersion, statusCode);
    }

    std::tuple<std::string, int, std::string> Http::parseStatusLineWithDescription(
        const std::string& line)
    {
        std::string_view lineView = trimAsciiWhitespace(line);
        size_t cursor = 0;

        auto httpVersionToken = nextSpaceSeparatedToken(lineView, cursor);
        auto statusToken = nextSpaceSeparatedToken(lineView, cursor);

        int statusCode = -1;
        parseIntToken(statusToken, statusCode);

        while (cursor < lineView.size() &&
               std::isspace(static_cast<unsigned char>(lineView[cursor])))
        {
            ++cursor;
        }

        std::string_view descriptionToken = lineView.substr(cursor);
        return std::make_tuple(
            std::string(httpVersionToken), statusCode, std::string(descriptionToken));
    }

    std::tuple<std::string, std::string, std::string> Http::parseRequestLine(
        const std::string& line)
    {
        std::string_view lineView = trimAsciiWhitespace(line);
        size_t cursor = 0;

        auto methodToken = nextSpaceSeparatedToken(lineView, cursor);
        auto uriToken = nextSpaceSeparatedToken(lineView, cursor);
        auto versionToken = nextSpaceSeparatedToken(lineView, cursor);

        return std::make_tuple(
            std::string(methodToken), std::string(uriToken), std::string(versionToken));
    }

    std::tuple<bool, std::string, HttpRequestPtr> Http::parseRequest(
        std::unique_ptr<Socket>& socket, int timeoutSecs)
    {
        HttpRequestPtr httpRequest;

        std::atomic<bool> requestInitCancellation(false);

        auto isCancellationRequested =
            makeCancellationRequestWithTimeout(timeoutSecs, requestInitCancellation);

        // Read first line
        auto line = socket->readLine(isCancellationRequested, timeoutSecs);
        if (!line)
        {
            return std::make_tuple(false, "Error reading HTTP request line", httpRequest);
        }

        // Parse and validate request line (GET /foo HTTP/1.1\r\n)
        std::string method;
        std::string uri;
        std::string httpVersion;
        std::string requestLineError;
        if (!parseHttpRequestLine(*line, method, uri, httpVersion, requestLineError))
        {
            return std::make_tuple(false, requestLineError, httpRequest);
        }

        // Retrieve and validate HTTP headers
        auto headersOpt = parseHttpHeaders(socket, isCancellationRequested, timeoutSecs);
        if (!headersOpt)
        {
            return std::make_tuple(false, "Error parsing HTTP headers", httpRequest);
        }
        auto headers = std::move(*headersOpt);

        auto transferEncodingIt = headers.find("Transfer-Encoding");
        if (transferEncodingIt != headers.end())
        {
            return std::make_tuple(
                false, std::string("HTTP request Transfer-Encoding is not supported"), httpRequest);
        }

        std::string body;
        auto contentLengthIt = headers.find("Content-Length");
        if (contentLengthIt != headers.end())
        {
            int contentLength = 0;

            std::string parseError;
            if (!parseContentLengthHeader(contentLengthIt->second, contentLength, parseError))
            {
                return std::make_tuple(false, parseError, httpRequest);
            }

            if (static_cast<size_t>(contentLength) > kMaxHttpBodySize)
            {
                return std::make_tuple(false, "HTTP request body is too large", httpRequest);
            }

            auto res =
                socket->readBytes(contentLength, nullptr, nullptr, isCancellationRequested, timeoutSecs);
            if (!res)
            {
                return std::make_tuple(
                    false, std::string("Error reading request body"), httpRequest);
            }
            body = std::move(*res);
        }

        // If the content was compressed with gzip, decode it
        if (headerContainsTokenCaseInsensitive(headers, "Content-Encoding", "gzip"))
        {
#ifdef IXWEBSOCKET_USE_ZLIB
            std::string decompressedPayload;
            if (!gzipDecompress(body, decompressedPayload, kMaxHttpBodySize))
            {
                return std::make_tuple(
                    false, std::string("Error during gzip decompression of the body"), httpRequest);
            }
            body = decompressedPayload;
#else
            std::string errorMsg("ixwebsocket was not compiled with gzip support on");
            return std::make_tuple(false, errorMsg, httpRequest);
#endif
        }

        httpRequest = std::make_shared<HttpRequest>(uri, method, httpVersion, body, headers);
        return std::make_tuple(true, "", httpRequest);
    }

    bool Http::sendResponse(HttpResponsePtr response, std::unique_ptr<Socket>& socket)
    {
        return sendResponse(response, socket, -1);
    }

    bool Http::sendResponse(HttpResponsePtr response, std::unique_ptr<Socket>& socket, int timeoutSecs)
    {
        if (!response || !socket || !isValidHttpHeaderValue(response->description))
        {
            return false;
        }

        for (const auto& [name, value] : response->headers)
        {
            if (!isValidHttpHeaderName(name) || !isValidHttpHeaderValue(value))
            {
                return false;
            }
        }

        // Check if chunked encoding should be used
        auto transferEncodingIt = response->headers.find("Transfer-Encoding");
        bool useChunked = transferEncodingIt != response->headers.end() &&
                          headerContainsTokenCaseInsensitive(
                              transferEncodingIt->second, "chunked");
        auto contentLengthIt = response->headers.find("Content-Length");
        if (useChunked && contentLengthIt != response->headers.end())
        {
            return false;
        }

        if (contentLengthIt != response->headers.end())
        {
            size_t contentLength = 0;
            std::string errorMsg;
            if (!parseContentLengthHeader(contentLengthIt->second, contentLength, errorMsg))
            {
                return false;
            }

            if (response->sendBody && contentLength != response->body.size())
            {
                return false;
            }
        }

        // Write the response to the socket after all consistency checks pass.
        std::stringstream ss;
        ss << "HTTP/1.1 ";
        ss << response->statusCode;
        ss << " ";
        ss << response->description;
        ss << "\r\n";

        if (!useChunked && contentLengthIt == response->headers.end())
        {
            ss << "Content-Length: " << response->body.size() << "\r\n";
        }
        for (const auto& [name, value] : response->headers)
        {
            ss << name << ": " << value << "\r\n";
        }
        ss << "\r\n";

        if (!socket->writeBytes(ss.str(), nullptr, timeoutSecs))
        {
            return false;
        }

        if (!response->sendBody)
        {
            return true;
        }

        if (useChunked)
        {
            // Send as chunked
            if (response->body.empty())
            {
                return socket->writeBytes("0\r\n\r\n", nullptr, timeoutSecs);
            }

            ss.str("");
            ss << std::hex << response->body.size() << "\r\n";
            if (!socket->writeBytes(ss.str(), nullptr, timeoutSecs))
                return false;
            if (!socket->writeBytes(response->body, nullptr, timeoutSecs))
                return false;
            if (!socket->writeBytes("\r\n0\r\n\r\n", nullptr, timeoutSecs))
                return false;
            return true;
        }

        // Send body
        if (response->body.empty())
        {
            return true;
        }

        return socket->writeBytes(response->body, nullptr, timeoutSecs);
    }
} // namespace ix
