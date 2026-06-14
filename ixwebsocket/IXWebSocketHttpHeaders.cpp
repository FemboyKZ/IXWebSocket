/*
 *  IXWebSocketHttpHeaders.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2018 Machine Zone, Inc. All rights reserved.
 */

#include "IXWebSocketHttpHeaders.h"

#include "IXHttp.h"
#include "IXSocket.h"
#include <algorithm>
#include <cctype>
#include <locale>
#include <optional>
#include <string_view>

namespace ix
{
    namespace
    {
        constexpr size_t kMaxHttpHeaderCount = 100;
        constexpr size_t kMaxHttpHeaderBytes = 64 * 1024;

        bool canCombineDuplicateHeader(std::string_view name)
        {
            return caseInsensitiveEquals(name, "Accept") ||
                   caseInsensitiveEquals(name, "Accept-Charset") ||
                   caseInsensitiveEquals(name, "Accept-Encoding") ||
                   caseInsensitiveEquals(name, "Accept-Language") ||
                   caseInsensitiveEquals(name, "Accept-Ranges") ||
                   caseInsensitiveEquals(name, "Access-Control-Allow-Headers") ||
                   caseInsensitiveEquals(name, "Access-Control-Allow-Methods") ||
                   caseInsensitiveEquals(name, "Access-Control-Expose-Headers") ||
                   caseInsensitiveEquals(name, "Access-Control-Request-Headers") ||
                   caseInsensitiveEquals(name, "Allow") ||
                   caseInsensitiveEquals(name, "Cache-Control") ||
                   caseInsensitiveEquals(name, "Connection") ||
                   caseInsensitiveEquals(name, "Pragma") ||
                   caseInsensitiveEquals(name, "Sec-WebSocket-Extensions") ||
                   caseInsensitiveEquals(name, "Sec-WebSocket-Protocol") ||
                   caseInsensitiveEquals(name, "TE") ||
                   caseInsensitiveEquals(name, "Trailer") ||
                   caseInsensitiveEquals(name, "Transfer-Encoding") ||
                   caseInsensitiveEquals(name, "Upgrade") ||
                   caseInsensitiveEquals(name, "Vary") ||
                   caseInsensitiveEquals(name, "Via") ||
                   caseInsensitiveEquals(name, "Warning");
        }

        bool canIgnoreDuplicateHeader(std::string_view name)
        {
            return caseInsensitiveEquals(name, "Set-Cookie");
        }
    }

    std::optional<WebSocketHttpHeaders> parseHttpHeaders(
        std::unique_ptr<Socket>& socket, const CancellationRequest& isCancellationRequested)
    {
        return parseHttpHeaders(socket, isCancellationRequested, -1);
    }

    std::optional<WebSocketHttpHeaders> parseHttpHeaders(
        std::unique_ptr<Socket>& socket,
        const CancellationRequest& isCancellationRequested,
        int timeoutSecs)
    {
        WebSocketHttpHeaders headers;
        size_t headerCount = 0;
        size_t headerBytes = 0;

        while (true)
        {
            auto lineOpt = socket->readLine(isCancellationRequested, timeoutSecs);
            if (!lineOpt)
            {
                return std::nullopt;
            }

            const std::string& line = *lineOpt;
            if (line.size() > kMaxHttpHeaderBytes - headerBytes)
            {
                return std::nullopt;
            }
            headerBytes += line.size();

            if (line == "\r\n")
            {
                break;
            }

            if (++headerCount > kMaxHttpHeaderCount)
            {
                return std::nullopt;
            }

            // line is a single header entry. split by ':', and add it to our
            // header map.
            auto colon = line.find(':');
            if (colon == std::string::npos || colon == 0)
            {
                return std::nullopt;
            }

            // colon is ':', usually colon+1 is ' ', and colon+2 is the start of the value.
            // some webservers do not put a space after the colon character, so
            // the start of the value might be farther than colon+2.
            // The spec says that space after the : should be discarded.
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

            std::string name(line.substr(0, colon));
            std::string value(line.substr(valueStart, valueEnd - valueStart));

            if (!isValidHttpHeaderName(name) || !isValidHttpHeaderValue(value))
            {
                return std::nullopt;
            }

            auto existing = headers.find(name);
            if (existing != headers.end())
            {
                if (caseInsensitiveEquals(std::string_view(name), std::string_view("Content-Length")))
                {
                    size_t existingLength = 0;
                    size_t newLength = 0;
                    std::string parseError;
                    if (!parseContentLengthHeader(existing->second, existingLength, parseError) ||
                        !parseContentLengthHeader(value, newLength, parseError) ||
                        existingLength != newLength)
                    {
                        return std::nullopt;
                    }
                }
                else if (canCombineDuplicateHeader(name))
                {
                    existing->second += ", ";
                    existing->second += value;
                }
                else if (canIgnoreDuplicateHeader(name))
                {
                    // WebSocketHttpHeaders cannot represent repeated Set-Cookie fields.
                    // Preserve the first value instead of comma-joining cookies incorrectly.
                }
                else
                {
                    return std::nullopt;
                }
                continue;
            }

            headers[name] = value;
        }

        return headers;
    }
} // namespace ix
