/*
 *  IXWebSocketHandshake.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2019 Machine Zone, Inc. All rights reserved.
 */

#include "IXWebSocketHandshake.h"

#include "IXBase64.h"
#include "IXHttp.h"
#include "IXSecureRandom.h"
#include "IXSocketConnect.h"
#include "IXUrlParser.h"
#include "IXUserAgent.h"
#include "IXWebSocketHandshakeKeyGen.h"
#include <algorithm>
#include <charconv>
#include <sstream>
#include <string_view>
#include <tuple>

namespace
{
    bool isBase64Character(char c)
    {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '+' || c == '/';
    }

    bool isValidSecWebSocketKey(const std::string& value)
    {
        if (value.size() != 24)
        {
            return false;
        }

        size_t padding = 0;
        bool seenPadding = false;
        for (size_t i = 0; i < value.size(); ++i)
        {
            if (value[i] == '=')
            {
                seenPadding = true;
                ++padding;
                if (i < value.size() - 2)
                {
                    return false;
                }
            }
            else
            {
                if (seenPadding || !isBase64Character(value[i]))
                {
                    return false;
                }
            }
        }

        if (padding != 2)
        {
            return false;
        }

        std::string decoded;
        if (!macaron::Base64::Decode(value, decoded).empty())
        {
            return false;
        }

        return decoded.size() == 16;
    }

    bool isRestrictedClientHandshakeHeader(std::string_view name)
    {
        return ix::caseInsensitiveEquals(name, "connection") ||
               ix::caseInsensitiveEquals(name, "upgrade") ||
               ix::caseInsensitiveEquals(name, "sec-websocket-key") ||
               ix::caseInsensitiveEquals(name, "sec-websocket-version") ||
               ix::caseInsensitiveEquals(name, "sec-websocket-extensions");
    }
} // namespace

namespace ix
{
    WebSocketHandshake::WebSocketHandshake(
        std::atomic<bool>& requestInitCancellation,
        std::unique_ptr<Socket>& socket,
        WebSocketPerMessageDeflatePtr& perMessageDeflate,
        WebSocketPerMessageDeflateOptions& perMessageDeflateOptions,
        std::atomic<bool>& enablePerMessageDeflate)
        : _requestInitCancellation(requestInitCancellation)
        , _socket(socket)
        , _perMessageDeflate(perMessageDeflate)
        , _perMessageDeflateOptions(perMessageDeflateOptions)
        , _enablePerMessageDeflate(enablePerMessageDeflate)
    {
    }

    bool WebSocketHandshake::genRandomBytes(size_t size, std::string& bytes)
    {
        bytes.assign(size, '\0');
        return secureRandomBytes(bytes.data(), bytes.size());
    }

    WebSocketInitResult WebSocketHandshake::sendErrorResponse(int code, const std::string& reason)
    {
        std::string customServer = getCustomServerHeader();
        std::string serverHeader = customServer.empty() ? userAgent() : customServer;
        if (!isValidHttpHeaderValue(reason) || !isValidHttpHeaderValue(serverHeader))
        {
            return WebSocketInitResult(false, code, reason);
        }

        std::stringstream ss;
        ss << "HTTP/1.1 ";
        ss << code;
        ss << " ";
        ss << reason;
        ss << "\r\n";
        ss << "Server: " << serverHeader << "\r\n";
        ss << "\r\n";

        // Socket write can only be cancelled through a timeout here, not manually.
        static std::atomic<bool> requestInitCancellation(false);
        auto isCancellationRequested =
            makeCancellationRequestWithTimeout(1, requestInitCancellation);

        if (!_socket->writeBytes(ss.str(), isCancellationRequested, 1))
        {
            return WebSocketInitResult(false, 500, "Timed out while sending error response");
        }

        return WebSocketInitResult(false, code, reason);
    }

    WebSocketInitResult WebSocketHandshake::clientHandshake(
        const std::string& url,
        const WebSocketHttpHeaders& extraHeaders,
        const std::string& protocol,
        const std::string& host,
        const std::string& path,
        int port,
        int timeoutSecs)
    {
        _requestInitCancellation = false;

        auto isCancellationRequested =
            makeCancellationRequestWithTimeout(timeoutSecs, _requestInitCancellation);

        if (!isValidHttpAuthority(host))
        {
            return WebSocketInitResult(false, 0, "Invalid HTTP host");
        }

        if (!isValidHttpRequestTarget(path))
        {
            return WebSocketInitResult(false, 0, "Invalid HTTP request target");
        }

        for (const auto& [name, value] : extraHeaders)
        {
            if (!isValidHttpHeaderName(name) || !isValidHttpHeaderValue(value))
            {
                return WebSocketInitResult(false, 0, "Invalid HTTP header: " + name);
            }

            if (isRestrictedClientHandshakeHeader(name))
            {
                return WebSocketInitResult(false, 0, "Restricted WebSocket header: " + name);
            }
        }

        if (extraHeaders.find("User-Agent") == extraHeaders.end() &&
            !isValidHttpHeaderValue(userAgent()))
        {
            return WebSocketInitResult(false, 0, "Invalid default User-Agent header value");
        }

        std::string errMsg;
        bool success = _socket->connect(host, port, errMsg, isCancellationRequested);

        if (!success)
        {
            std::stringstream ss;
            ss << "Unable to connect to " << host << " on port " << port << ", error: " << errMsg;
            return WebSocketInitResult(false, 0, ss.str());
        }

        // Generate a random 16 bytes string and base64 encode it.
        //
        // See https://stackoverflow.com/questions/18265128/what-is-sec-websocket-key-for
        std::string secWebSocketKeyBytes;
        if (!genRandomBytes(16, secWebSocketKeyBytes))
        {
            return WebSocketInitResult(false, 0, "Unable to generate Sec-WebSocket-Key");
        }
        std::string secWebSocketKey = macaron::Base64::Encode(secWebSocketKeyBytes);

        std::stringstream ss;
        ss << "GET " << path << " HTTP/1.1\r\n";
        if (extraHeaders.find("Host") == extraHeaders.end())
        {
            ss << "Host: " << formatHttpHost(host) << ":" << port << "\r\n";
        }
        ss << "Upgrade: websocket\r\n";
        ss << "Connection: Upgrade\r\n";
        ss << "Sec-WebSocket-Version: 13\r\n";
        ss << "Sec-WebSocket-Key: " << secWebSocketKey << "\r\n";

        // User-Agent can be customized by users
        if (extraHeaders.find("User-Agent") == extraHeaders.end())
        {
            ss << "User-Agent: " << userAgent() << "\r\n";
        }

        // Set an origin header if missing
        if (extraHeaders.find("Origin") == extraHeaders.end())
        {
            ss << "Origin: " << protocol << "://" << formatHttpHost(host) << ":" << port << "\r\n";
        }

        for (const auto& [name, value] : extraHeaders)
        {
            ss << name << ": " << value << "\r\n";
        }

        if (_enablePerMessageDeflate)
        {
            ss << _perMessageDeflateOptions.generateHeader();
        }

        ss << "\r\n";

        if (!_socket->writeBytes(ss.str(), isCancellationRequested, timeoutSecs))
        {
            return WebSocketInitResult(
                false, 0, std::string("Failed sending GET request to ") + url);
        }

        // Read HTTP status line
        auto line = _socket->readLine(isCancellationRequested, timeoutSecs);
        if (!line)
        {
            return WebSocketInitResult(
                false, 0, std::string("Failed reading HTTP status line from ") + url);
        }

        // Validate status
        auto [httpVersion, status] = Http::parseStatusLine(*line);

        // HTTP/1.0 is too old.
        if (httpVersion != "HTTP/1.1")
        {
            std::stringstream ss;
            ss << "Expecting HTTP/1.1, got " << httpVersion << ". "
               << "Rejecting connection to " << url << ", status: " << status
               << ", HTTP Status line: " << *line;
            return WebSocketInitResult(false, status, ss.str());
        }

        auto headersOpt = parseHttpHeaders(_socket, isCancellationRequested, timeoutSecs);
        if (!headersOpt)
        {
            return WebSocketInitResult(false, status, "Error parsing HTTP headers");
        }
        auto headers = std::move(*headersOpt);

        // We want an 101 HTTP status for websocket, otherwise it could be
        // a redirection (like 301)
        if (status != 101)
        {
            std::stringstream ss;
            ss << "Expecting status 101 (Switching Protocol), got " << status
               << " status connecting to " << url << ", HTTP Status line: " << *line;

            return WebSocketInitResult(false, status, ss.str(), headers, path);
        }

        // Check the presence of the connection field
        if (headers.find("connection") == headers.end())
        {
            std::string errorMsg("Missing connection value");
            return WebSocketInitResult(false, status, errorMsg);
        }

        // Connection can include multiple comma-separated tokens.
        if (!headerContainsTokenCaseInsensitive(headers["connection"], "upgrade"))
        {
            std::stringstream ss;
            ss << "Invalid connection value: " << headers["connection"];
            return WebSocketInitResult(false, status, ss.str());
        }

        if (headers.find("upgrade") == headers.end())
        {
            return WebSocketInitResult(false, status, "Missing Upgrade value");
        }

        if (!headerContainsTokenCaseInsensitive(headers["upgrade"], "websocket"))
        {
            std::stringstream ss;
            ss << "Invalid upgrade value: " << headers["upgrade"];
            return WebSocketInitResult(false, status, ss.str());
        }

        char output[29] = {};
        WebSocketHandshakeKeyGen::generate(secWebSocketKey, output);
        if (std::string(output) != headers["sec-websocket-accept"])
        {
            std::string errorMsg("Invalid Sec-WebSocket-Accept value");
            return WebSocketInitResult(false, status, errorMsg);
        }

        std::string selectedProtocol;
        auto selectedProtocolIt = headers.find("sec-websocket-protocol");
        if (selectedProtocolIt != headers.end())
        {
            const auto selectedTokens = splitHeaderTokens(selectedProtocolIt->second);
            if (selectedTokens.size() != 1 || !isValidHttpHeaderName(selectedTokens.front()))
            {
                return WebSocketInitResult(
                    false, status, "Invalid Sec-WebSocket-Protocol value");
            }

            auto requestedProtocolIt = extraHeaders.find("Sec-WebSocket-Protocol");
            if (requestedProtocolIt == extraHeaders.end())
            {
                return WebSocketInitResult(
                    false, status, "Unexpected Sec-WebSocket-Protocol value");
            }

            const auto requestedTokens = splitHeaderTokens(requestedProtocolIt->second);
            auto requestedIt = std::find(requestedTokens.begin(),
                                         requestedTokens.end(),
                                         selectedTokens.front());
            if (requestedIt == requestedTokens.end())
            {
                return WebSocketInitResult(
                    false, status, "Unexpected Sec-WebSocket-Protocol value");
            }

            selectedProtocol = std::string(selectedTokens.front());
        }

        if (_enablePerMessageDeflate)
        {
            // Parse the server response. Does it support deflate ?
            std::string header = headers["sec-websocket-extensions"];
            WebSocketPerMessageDeflateOptions webSocketPerMessageDeflateOptions(header);

            // If the server does not support that extension, disable it.
            if (!webSocketPerMessageDeflateOptions.enabled())
            {
                _enablePerMessageDeflate = false;
            }
            // Otherwise try to initialize the deflate engine (zlib)
            else if (!_perMessageDeflate->init(webSocketPerMessageDeflateOptions))
            {
                return WebSocketInitResult(
                    false, 0, "Failed to initialize per message deflate engine");
            }
        }

        return WebSocketInitResult(true, status, "", headers, path, selectedProtocol);
    }

    WebSocketInitResult WebSocketHandshake::serverHandshake(int timeoutSecs,
                                                            bool enablePerMessageDeflate,
                                                            HttpRequestPtr request,
                                                            const std::vector<std::string>& subProtocols)
    {
        _requestInitCancellation = false;

        auto isCancellationRequested =
            makeCancellationRequestWithTimeout(timeoutSecs, _requestInitCancellation);

        std::string method;
        std::string uri;
        std::string httpVersion;

        if (request)
        {
            method = request->method;
            uri = request->uri;
            httpVersion = request->version;
        }
        else
        {
            // Read first line
            auto line = _socket->readLine(isCancellationRequested, timeoutSecs);
            if (!line)
            {
                return sendErrorResponse(400, "Error reading HTTP request line");
            }

            // Validate request line (GET /foo HTTP/1.1\r\n)
            std::string requestLineError;
            if (!parseHttpRequestLine(*line, method, uri, httpVersion, requestLineError))
            {
                return sendErrorResponse(400, requestLineError);
            }
        }

        if (method != "GET")
        {
            return sendErrorResponse(400, "Invalid HTTP method, need GET, got " + method);
        }

        if (httpVersion != "HTTP/1.1")
        {
            return sendErrorResponse(400,
                                     "Invalid HTTP version, need HTTP/1.1, got: " + httpVersion);
        }

        WebSocketHttpHeaders headers;
        if (request)
        {
            headers = request->headers;
        }
        else
        {
            // Retrieve and validate HTTP headers
            auto headersOpt = parseHttpHeaders(_socket, isCancellationRequested, timeoutSecs);
            if (!headersOpt)
            {
                return sendErrorResponse(400, "Error parsing HTTP headers");
            }
            headers = std::move(*headersOpt);
        }

        auto secWebSocketKeyIt = headers.find("sec-websocket-key");
        if (secWebSocketKeyIt == headers.end())
        {
            return sendErrorResponse(400, "Missing Sec-WebSocket-Key value");
        }

        if (!isValidSecWebSocketKey(secWebSocketKeyIt->second))
        {
            return sendErrorResponse(400, "Invalid Sec-WebSocket-Key value");
        }

        if (headers.find("connection") == headers.end())
        {
            return sendErrorResponse(400, "Missing Connection header");
        }

        if (!headerContainsTokenCaseInsensitive(headers["connection"], "upgrade"))
        {
            return sendErrorResponse(
                400, "Invalid Connection header, need token Upgrade, got " + headers["connection"]);
        }

        if (headers.find("upgrade") == headers.end())
        {
            return sendErrorResponse(400, "Missing Upgrade header");
        }

        if (!headerContainsTokenCaseInsensitive(headers["upgrade"], "websocket"))
        {
            return sendErrorResponse(400,
                                     "Invalid Upgrade header, "
                                     "need WebSocket, got " +
                                         headers["upgrade"]);
        }

        if (headers.find("sec-websocket-version") == headers.end())
        {
            return sendErrorResponse(400, "Missing Sec-WebSocket-Version value");
        }

        {
            const std::string& versionHeader = headers["sec-websocket-version"];
            int version = 0;
            auto [ptr, ec] = std::from_chars(
                versionHeader.data(), versionHeader.data() + versionHeader.size(), version);

            if (ec != std::errc() || ptr != versionHeader.data() + versionHeader.size() ||
                version != 13)
            {
                return sendErrorResponse(400,
                                         "Invalid Sec-WebSocket-Version, "
                                         "need 13, got " +
                                             versionHeader);
            }
        }

        char output[29] = {};
        WebSocketHandshakeKeyGen::generate(secWebSocketKeyIt->second, output);

        std::stringstream ss;
        ss << "HTTP/1.1 101 Switching Protocols\r\n";
        ss << "Sec-WebSocket-Accept: " << std::string(output) << "\r\n";
        ss << "Upgrade: websocket\r\n";
        ss << "Connection: Upgrade\r\n";
        std::string customServer = getCustomServerHeader();
        std::string serverHeader = customServer.empty() ? userAgent() : customServer;
        if (!isValidHttpHeaderValue(serverHeader))
        {
            return WebSocketInitResult(false, 0, "Invalid Server header value");
        }
        ss << "Server: " << serverHeader << "\r\n";

        // Handle sub-protocol negotiation
        std::string selectedProtocol;
        auto protocolIt = headers.find("sec-websocket-protocol");
        if (!subProtocols.empty() && protocolIt != headers.end())
        {
            const auto clientProtocols = splitHeaderTokens(protocolIt->second);
            for (const auto& serverProtocol : subProtocols)
            {
                auto clientIt = std::find(clientProtocols.begin(),
                                          clientProtocols.end(),
                                          std::string_view(serverProtocol));
                if (clientIt != clientProtocols.end())
                {
                    if (!isValidHttpHeaderName(serverProtocol))
                    {
                        return WebSocketInitResult(false, 0, "Invalid Sec-WebSocket-Protocol value");
                    }

                    selectedProtocol = serverProtocol;
                    ss << "Sec-WebSocket-Protocol: " << serverProtocol << "\r\n";
                    break;
                }
            }
        }

        // Parse the client headers. Does it support deflate ?
        std::string header = headers["sec-websocket-extensions"];
        WebSocketPerMessageDeflateOptions webSocketPerMessageDeflateOptions(header);

        // If the client has requested that extension,
        if (webSocketPerMessageDeflateOptions.enabled() && enablePerMessageDeflate)
        {
            _enablePerMessageDeflate = true;

            if (!_perMessageDeflate->init(webSocketPerMessageDeflateOptions))
            {
                return WebSocketInitResult(
                    false, 0, "Failed to initialize per message deflate engine");
            }
            ss << webSocketPerMessageDeflateOptions.generateHeader();
        }

        ss << "\r\n";

        if (!_socket->writeBytes(ss.str(), isCancellationRequested, timeoutSecs))
        {
            return WebSocketInitResult(
                false, 0, std::string("Failed sending response to remote end"));
        }

        return WebSocketInitResult(true, 101, "", headers, uri, selectedProtocol);
    }
} // namespace ix
